"""Record observer/fault injector, used only between independent test peers."""
import socket
import struct
import time

from bend_tls_client_check import Proxy, Epoch, record, frame, handshake, HRR


class ServerProxy(Proxy):
    def protected(self, encoded, direction):
        incoming, outgoing = self.epochs(direction)
        sequence = incoming.sequence
        plaintext = incoming.decrypt(encoded)
        inner = len(plaintext) - 1
        while inner >= 0 and plaintext[inner] == 0:
            inner -= 1
        assert inner >= 0
        kind, content = plaintext[inner], plaintext[:inner]
        event = dict(direction=direction, protected_type=kind, bytes=len(content))
        update = False
        if kind == 21:
            event["alert"] = list(content)
        if kind == 22:
            types, cursor = [], 0
            original_size = len(content)
            while cursor + 4 <= original_size:
                typ = content[cursor]
                size = int.from_bytes(content[cursor+1:cursor+4], "big")
                assert cursor + 4 + size <= original_size
                types.append(typ)
                if typ == 15:
                    event["signature_scheme"] = int.from_bytes(content[cursor+4:cursor+6], "big")
                if typ == 20:
                    if direction == "server":
                        self.server_finished = True
                    else:
                        self.client_finished = True
                        name = self.case["name"]
                        if name == "altered-client-finished":
                            content = content[:-1] + bytes([content[-1] ^ 1])
                            self.mutation_applied = True
                        elif name == "finished-coalesced-message":
                            content += handshake(24, b"\x00")
                            self.mutation_applied = True
                        elif name == "finished-partial-tail":
                            content += b"\x18"
                            self.mutation_applied = True
                if typ == 24:
                    event["keyupdate"] = list(content[cursor+4:cursor+4+size])
                    update = True
                cursor += 4 + size
            event["handshakes"] = types
        self.events.append(event)
        if outgoing is None:
            outgoing = Epoch(incoming.secret)
            outgoing.sequence = sequence
        # All outgoing application records use a distinct epoch so inserted
        # test records can advance sequence numbers without changing the peer.
        if direction == "client" and kind == 23 and not self.mutation_applied:
            name = self.case["name"]
            if name == "late-client-ccs":
                self.emit(self.upstream, frame(20,b"\x01"))
                self.mutation_applied = True
            injection = {"client-keyupdate": handshake(24,b"\x01"),
                         "malformed-client-keyupdate": handshake(24,b"\x02"),
                         "client-session-ticket": handshake(4,bytes(8)+b"\x00\x00\x01x\x00\x00"),
                         "client-post-handshake-auth": handshake(13,b"\x00\x00\x00"),
                         "coalesced-keyupdates": handshake(24,b"\x00") + handshake(24,b"\x00")}.get(name)
            if injection is not None:
                self.emit(self.upstream,outgoing.encrypt(injection+b"\x16"))
                self.events.append(dict(direction="client", inserted_handshake=injection.hex()))
                self.mutation_applied = True
                if name == "client-keyupdate":
                    self.injected_update = True
                    outgoing = outgoing.update()
                    self.client_out = outgoing
        encoded = outgoing.encrypt(content + bytes([kind]))
        if direction == "client" and self.case["name"] == "modified-client-record" and kind == 22 and self.client_finished:
            encoded = encoded[:-1] + bytes([encoded[-1]^1])
            self.mutation_applied = True
        if update:
            if direction == "server":
                self.server_app, self.server_out = incoming.update(), outgoing.update()
            else:
                self.client_app, self.client_out = incoming.update(), outgoing.update()
        return encoded, kind, content

    def pump(self, source, target, direction):
        try:
            while not self.stop.is_set():
                encoded = record(source)
                if encoded is None:
                    break
                kind = encoded[0]
                name = self.case["name"]
                if kind == 22:
                    if direction == "server":
                        retry = encoded[11:43] == HRR
                        self.hrr_count += int(retry)
                        self.events.append(dict(direction=direction, server_hello=True, retry=retry))
                    else:
                        self.client_hellos += 1
                        self.events.append(dict(direction=direction, client_hello=self.client_hellos))
                        if self.client_hellos == 2 and name in {"altered-retry-cookie", "altered-retry-random"}:
                            changed = bytearray(encoded)
                            if name == "altered-retry-random":
                                changed[11] ^= 1
                            else:
                                body = encoded[9:]
                                cursor = 35 + body[34]
                                cursor += 2 + int.from_bytes(body[cursor:cursor+2],"big")
                                cursor += 1 + body[cursor]
                                cursor += 2
                                while cursor < len(body):
                                    typ, size = struct.unpack(">HH", body[cursor:cursor+4])
                                    if typ == 44:
                                        changed[9+cursor+4+size-1] ^= 1
                                        break
                                    cursor += 4+size
                                else:
                                    raise AssertionError("CH2 did not contain the HRR cookie")
                            encoded = bytes(changed)
                            self.mutation_applied = True
                        if name == "coalesced" and self.client_hellos == 1:
                            self.emit(target,encoded+frame(20,b"\x01"))
                            self.events.append(dict(direction="client",coalesced_records=2))
                            continue
                if kind == 21:
                    self.events.append(dict(direction=direction,alert=list(encoded[5:])))
                if kind == 23:
                    encoded, _, _ = self.protected(encoded,direction)
                self.emit(target,encoded)
        except (OSError,EOFError) as error:
            self.events.append(dict(direction=direction,transport_end=str(error)))
        except Exception as error:
            self.errors.append(f"{direction}: {type(error).__name__}: {error}")
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass
