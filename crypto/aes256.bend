import Base
import ./aes128.bend as A
import ./bytes.bend as B

# FIPS 197 AES-256. Reuse arithmetic S-box and state operations; every
# branch/index below is a public key-schedule/round position.
def expand.write(+i: U32, rcon: U32, byte: U32, pair: Array<U32> & U32) -> A.Expanded:
  (keys, old) = pair
  A.Expanded{Array.set(U32,keys,i,U32.xor(old,byte)),rcon}

def expand.rotated(+i: U32, keys: Array<U32>, pair: U32 & U32) -> A.Expanded:
  (rcon, byte) = pair
  expand.write(i,rcon,byte,Array.get(U32,keys,U32.sub(i,32)))

def expand.transformed(rot: Bool, sub: Bool, +i: U32, keys: Array<U32>, +rcon: U32, byte: U32) -> A.Expanded:
  match rot sub:
    case True{} _:
      expand.rotated(i,keys,A.expand.rcon(U32.is_eq(U32.mod(i,4),0),U32.is_eq(U32.mod(i,4),3),rcon,A.sbox(byte)))
    case False{} True{}: expand.write(i,rcon,A.sbox(byte),Array.get(U32,keys,U32.sub(i,32)))
    case _ _: expand.write(i,rcon,byte,Array.get(U32,keys,U32.sub(i,32)))

def expand.got(+rot: Bool, sub: Bool, i: U32, rcon: U32, pair: Array<U32> & U32) -> A.Expanded:
  (keys, byte) = pair
  expand.transformed(rot,sub,i,keys,rcon,byte)

def expand.go(left: Nat, +i: U32, state: A.Expanded) -> Array<U32>:
  match left state:
    case 0n A.Expanded{keys,_}: keys
    case 1n+p A.Expanded{keys,rcon}:
      +rot = U32.is_lt(U32.mod(i,32),4)
      sub = Bool.and(U32.is_ge(U32.mod(i,32),16),U32.is_lt(U32.mod(i,32),20))
      expand.go(p,U32.inc(i),expand.got(rot,sub,i,rcon,Array.get(U32,keys,A.expand.index(rot,i))))

def expand.raw(key: List<&2,U32>) -> Array<U32>:
  expand.go(208n,32,A.Expanded{A.from_bytes(key,0,Array.new(U32,8n,0)),1})

def rounds(left: Nat, +round: U32, work: A.Round) -> A.Round:
  match left work:
    case 0n A.Round{keys,state}: A.add(16n,0,14,A.Round{keys,A.shifted(state)})
    case 1n+p A.Round{keys,state}:
      rounds(p,U32.inc(round),A.add(16n,0,round,A.Round{keys,A.mixed(4n,0,A.shifted(state))}))

def block(keys: Array<U32>, input: List<&2,U32>) -> Array<U32> & List<&2,U32>:
  A.finished(rounds(13n,1,A.add(16n,0,0,A.Round{keys,A.from_bytes(input,0,Array.new(U32,4n,0))})))

def encrypt.checked(valid: Bool, key: List<&2,U32>, input: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match valid:
    case False{}: None{}
    case True{}: A.encrypt.got(block(expand.raw(key),input))

def encrypt(+key: List<&2,U32>, +input: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  encrypt.checked(Bool.and(Bool.and(Nat.is_eq(B.length(key),32n),B.valid(key)),Bool.and(Nat.is_eq(B.length(input),16n),B.valid(input))),key,input)
