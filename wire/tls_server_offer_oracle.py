"""Test-only no-PSK schedule oracle for a PSK + early_data ClientHello offer.

This deliberately limited raw peer checks rejection of PSK/0-RTT selection and
Finished/application keys. Normal certificate verification is separately tested
with OpenSSL, Python and Go; this helper makes no certificate-authentication claim.
"""
import hashlib
import hmac

from bend_tls_client_check import Epoch, record, frame, handshake
from tls_server_handshake_check import hello
from tls_extensions_check import entry, vector
from x25519_check import ALICE, ALICE_PUBLIC, reference


def label(secret, name, context, size=32):
    name=b"tls13 "+name
    info=size.to_bytes(2,"big")+bytes([len(name)])+name+bytes([len(context)])+context
    result,block,index=b"",b"",1
    while len(result)<size:
        block=hmac.digest(secret,block+info+bytes([index]),"sha256")
        result+=block
        index+=1
    return result[:size]


def extensions(data):
    length=int.from_bytes(data[:2],"big")
    assert length==len(data)-2
    result={}
    cursor=2
    while cursor<len(data):
        kind=int.from_bytes(data[cursor:cursor+2],"big")
        size=int.from_bytes(data[cursor+2:cursor+4],"big")
        assert kind not in result and cursor+4+size<=len(data)
        result[kind]=data[cursor+4:cursor+4+size]
        cursor+=4+size
    return result


def ignored_offer(peer, *, early=True):
    ids=vector(vector(b"synthetic-unused-identity")+bytes(4))
    binders=vector(b"\x20"+bytes(32))
    extra=entry(45,b"\x01\x01")+(entry(42,b"") if early else b"")+entry(41,ids+binders)
    ch=hello({51:vector(b"\x00\x1d"+vector(ALICE_PUBLIC))},extra=extra)
    peer.sendall(frame(22,ch))
    sh=record(peer)
    assert sh[0]==22 and sh[5]==2
    body=sh[9:]
    cursor=35+body[34]+3
    selected=extensions(body[cursor:])
    assert 41 not in selected and selected[43]==b"\x03\x04"
    share=selected[51]
    assert share[:4]==b"\x00\x1d\x00\x20"
    shared=reference(ALICE,share[4:])
    empty=hashlib.sha256(b"").digest()
    early_secret=hmac.digest(bytes(32),bytes(32),"sha256")
    handshake_secret=hmac.digest(label(early_secret,b"derived",empty),shared,"sha256")
    transcript=ch+sh[5:]
    chsh=hashlib.sha256(transcript).digest()
    client_secret=label(handshake_secret,b"c hs traffic",chsh)
    server_secret=label(handshake_secret,b"s hs traffic",chsh)
    read,write=Epoch(server_secret),Epoch(client_secret)
    pending=b""
    types=[]
    while 20 not in types:
        encoded=record(peer)
        if encoded[0]==20:
            continue
        plaintext=read.decrypt(encoded)
        assert plaintext[-1]==22
        pending+=plaintext[:-1]
        while len(pending)>=4:
            size=int.from_bytes(pending[1:4],"big")
            if len(pending)<4+size:
                break
            message,pending=pending[:4+size],pending[4+size:]
            kind=message[0]
            types.append(kind)
            if kind==8:
                assert 42 not in extensions(message[4:])
            if kind==20:
                want=hmac.digest(label(server_secret,b"finished",b""),hashlib.sha256(transcript).digest(),"sha256")
                assert hmac.compare_digest(message[4:],want)
            transcript+=message
    assert types==[8,11,15,20] and not pending
    hash_finished=hashlib.sha256(transcript).digest()
    client_finished=hmac.digest(label(client_secret,b"finished",b""),hash_finished,"sha256")
    peer.sendall(write.encrypt(handshake(20,client_finished)+b"\x16"))
    master=hmac.digest(label(handshake_secret,b"derived",empty),bytes(32),"sha256")
    app_write=Epoch(label(master,b"c ap traffic",hash_finished))
    app_read=Epoch(label(master,b"s ap traffic",hash_finished))
    peer.sendall(app_write.encrypt(b"ping\x17"))
    assert app_read.decrypt(record(peer))==b"ping\x17"
    assert app_read.decrypt(record(peer))==b"\x01\x00\x15"
    peer.sendall(app_write.encrypt(b"\x01\x00\x15"))
    return dict(offered_psk=True,offered_early_data=early,server_selected_psk=False,
                server_accepted_early_data=False,no_psk_finished_verified=True,
                handshakes=types,application="ping",close_notify=True)
