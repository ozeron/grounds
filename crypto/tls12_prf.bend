import Base
import ./bytes.bend as B
import ./hmac.bend as H256
import ./hmac_sha384.bend as H384

# TLS 1.2 PRF (RFC 5246 section 5): P_hash with HMAC over the suite hash,
# SHA-256 or SHA-384 (RFC 5288/5289, RFC 7905). Extended master secret is
# RFC 7627 section 4; the key block is RFC 5246 section 6.3; Finished
# verify_data is RFC 5246 section 7.4.9 (12 bytes). Secrets are ordinary
# lists: logical one-use ownership only, see crypto/RUNTIME_REVIEW.md (M7).

def mac(large: Bool, key: List<&2,U32>, message: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match large:
    case True{}: H384.digest(key,message)
    case False{}: H256.digest(key,message)

def append_block(acc: List<&2,U32>, block: Maybe<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match block:
    case None{}: None{}
    case Some{block}: Some{B.append(acc,block)}

# A(1) = HMAC(secret, seed); output block i = HMAC(secret, A(i) || seed);
# A(i+1) = HMAC(secret, A(i)). fuel counts the remaining output blocks.
def p_hash.go(fuel: Nat, +large: Bool, +secret: List<&2,U32>, +seed: List<&2,U32>, a: Maybe<&2,List<&2,U32>>, acc: Maybe<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match fuel a acc:
    case 0n _ acc: acc
    case 1n+p Some{+a} Some{acc}: p_hash.go(p,large,secret,seed,mac(large,secret,a),append_block(acc,mac(large,secret,B.append(a,seed))))
    case _ _ _: None{}

def finish(length: Nat, result: Maybe<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match result:
    case None{}: None{}
    case Some{bytes}: Some{List.take(&2,U32,bytes,length)}

def prf.checked(ok: Bool, +large: Bool, +secret: List<&2,U32>, +seed: List<&2,U32>, +length: Nat) -> Maybe<&2,List<&2,U32>>:
  match ok:
    case False{}: None{}
    case True{}:
      +size = Bool.pick(Nat,large,48n,32n)
      finish(length,p_hash.go(Nat.div(Nat.add(length,Nat.sub(size,1n)),size),large,secret,seed,mac(large,secret,seed),Some{[]}))

# PRF(secret, label, seed) = P_<hash>(secret, label || seed), truncated.
# Bounded to 1 KiB of output; TLS uses at most 88 bytes (ChaCha key block).
def prf(large: Bool, +secret: List<&2,U32>, +label: List<&2,U32>, +seed: List<&2,U32>, +length: Nat) -> Maybe<&2,List<&2,U32>>:
  prf.checked(Bool.and(Bool.and(Nat.is_ge(length,1n),Nat.is_le(length,1024n)),
    Bool.and(Bool.and(B.valid(secret),Nat.is_le(B.length(secret),1024n)),
      Bool.and(Bool.and(B.valid(label),Nat.is_ge(B.length(label),1n)),Bool.and(B.valid(seed),Nat.is_le(B.length(seed),1024n))))),
    large,secret,B.append(label,seed),length)

# RFC 7627 section 4: master_secret = PRF(pre_master_secret,
# "extended master secret", session_hash)[0..47]; session_hash is the suite
# hash of the handshake messages through ClientKeyExchange.
def master_secret(large: Bool, premaster: List<&2,U32>, session_hash: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  prf(large,premaster,[101,120,116,101,110,100,101,100,32,109,97,115,116,101,114,32,115,101,99,114,101,116],session_hash,48n)

# RFC 5246 section 6.3: key_block = PRF(master, "key expansion",
# server_random || client_random). AEAD suites have no MAC keys.
def key_block(large: Bool, master: List<&2,U32>, server_random: List<&2,U32>, client_random: List<&2,U32>, length: Nat) -> Maybe<&2,List<&2,U32>>:
  prf(large,master,[107,101,121,32,101,120,112,97,110,115,105,111,110],B.append(server_random,client_random),length)

# RFC 5246 section 7.4.9: verify_data = PRF(master, finished_label,
# Hash(handshake_messages))[0..11].
def verify_data(large: Bool, client: Bool, master: List<&2,U32>, hash: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  prf(large,master,Bool.pick(List<&2,U32>,client,[99,108,105,101,110,116,32,102,105,110,105,115,104,101,100],[115,101,114,118,101,114,32,102,105,110,105,115,104,101,100]),hash,12n)

# XOR every byte before deciding; no early exit on a wrong byte.
def difference(expected: List<&2,U32>, supplied: List<&2,U32>, +acc: U32) -> U32:
  match expected supplied:
    case Nil{} Nil{}: acc
    case Con{a,at} Con{b,bt}: difference(at,bt,U32.or(acc,U32.xor(a,b)))
    case _ _: 1

def same(expected: List<&2,U32>, supplied: List<&2,U32>) -> Bool:
  U32.is_eq(difference(expected,supplied,0),0)
