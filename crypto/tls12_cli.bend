import Base
import ./tls12_prf.bend as P
import ./traffic.bend as T
import ./bytes.bend as B
import ../io/io.bend as Io

# Synthetic evaluator for the TLS 1.2 PRF and AEAD record owners (M7).
# Inputs are files; the seed command reaches counter boundaries directly,
# which protocol callers must never do with a live owner.

def error(error: T.Error) -> String:
  match error:
    case T.Invalid{}: "invalid"
    case T.Authentication{}: "authentication"
    case T.Exhausted{}: "exhausted"
    case T.Closed{}: "closed"
    case T.UpdateLimit{}: "update-limit"
    case T.UsageLimit{}: "usage-limit"

def emit(label: String, value: Maybe<&2,List<&2,U32>>) -> IO(Unit):
  match value:
    case None{}: IO.print(label ++ ":none")
    case Some{bytes}: IO.print(label ++ ":" ++ B.hex(bytes))

def large(name: String) -> Bool:
  String.eq(name,"384")

def number(text: String) -> U32:
  Maybe.default(&2,U32,U32.read(text),0)

def seed_epoch(epoch: T.Epoch, high: U32, low: U32) -> T.Epoch:
  match epoch:
    case T.Aes12Ready{key,salt,_}: T.Aes12Ready{key,salt,T.Counter{high,low}}
    case T.Chacha12Ready{key,iv,_}: T.Chacha12Ready{key,iv,T.Counter{high,low}}
    case epoch: epoch

def seed_write(owner: Maybe<&1,T.WriteKey>, high: U32, low: U32) -> Maybe<&1,T.WriteKey>:
  match owner:
    case Some{T.WriteKey{epoch,generation}}: Some{T.WriteKey{seed_epoch(epoch,high,low),generation}}
    case None{}: None{}

def seed_read(owner: Maybe<&1,T.ReadKey>, high: U32, low: U32) -> Maybe<&1,T.ReadKey>:
  match owner:
    case Some{T.ReadKey{epoch}}: Some{T.ReadKey{seed_epoch(epoch,high,low)}}
    case None{}: None{}

def seal_last(pair: T.WriteKey & Result<&2,&2,T.Error,List<&2,U32>>) -> IO(Unit):
  (_,result) = pair
  match result:
    case Fail{why}: IO.print("seal-error:" ++ error(why))
    case Done{fragment}: IO.print("fragment:" ++ B.hex(fragment))

def seal_loop(values: List<&2,List<&2,U32>>, +kind: U32, pair: T.WriteKey & Result<&2,&2,T.Error,List<&2,U32>>) -> IO(Unit):
  match values:
    case Nil{}: seal_last(pair)
    case Con{value,rest}:
      (owner,result) = pair
      match result:
        case Fail{why}: IO.print("seal-error:" ++ error(why))
        case Done{fragment}:
          do IO<Unit>:
            IO.print("fragment:" ++ B.hex(fragment))
            seal_loop(rest,kind,T.seal12(owner,kind,value))

def open_last(pair: T.ReadKey & Result<&2,&2,T.Error,List<&2,U32>>) -> IO(Unit):
  (_,result) = pair
  match result:
    case Fail{why}: IO.print("open-error:" ++ error(why))
    case Done{plaintext}: IO.print("plaintext:" ++ B.hex(plaintext))

def open_loop(values: List<&2,List<&2,U32>>, +kind: U32, pair: T.ReadKey & Result<&2,&2,T.Error,List<&2,U32>>) -> IO(Unit):
  match values:
    case Nil{}: open_last(pair)
    case Con{value,rest}:
      (owner,result) = pair
      match result:
        case Fail{why}: IO.print("open-error:" ++ error(why))
        case Done{plaintext}:
          do IO<Unit>:
            IO.print("plaintext:" ++ B.hex(plaintext))
            open_loop(rest,kind,T.open12(owner,kind,value))

def seal_owner(owner: Maybe<&1,T.WriteKey>, +kind: U32, values: List<&2,List<&2,U32>>) -> IO(Unit):
  match owner values:
    case None{} _: IO.print("key:invalid")
    case Some{_} Nil{}: IO.print("key:valid")
    case Some{owner} Con{value,rest}: seal_loop(rest,kind,T.seal12(owner,kind,value))

def open_owner(owner: Maybe<&1,T.ReadKey>, +kind: U32, values: List<&2,List<&2,U32>>) -> IO(Unit):
  match owner values:
    case None{} _: IO.print("key:invalid")
    case Some{_} Nil{}: IO.print("key:valid")
    case Some{owner} Con{value,rest}: open_loop(rest,kind,T.open12(owner,kind,value))

def read_files(paths: List<String>) -> IO(List<&2,List<&2,U32>>):
  match paths:
    case Nil{}: IO.pure(List<&2,List<&2,U32>>,[])
    case Con{path,rest}:
      do IO<List<&2,List<&2,U32>>>:
        bytes : List<&2,U32> <- Io.read_bytes(path)
        tail : List<&2,List<&2,U32>> <- read_files(rest)
        IO.pure(List<&2,List<&2,U32>>,Con{bytes,tail})

def derive3(values: List<&2,List<&2,U32>>, hash: String, length: String, mode: String) -> IO(Unit):
  match values:
    case [a,b,c]:
      match mode:
        case "prf": emit("prf",P.prf(large(hash),a,b,c,U32.to_nat(number(length))))
        case _: emit("keys",P.key_block(large(hash),a,b,c,U32.to_nat(number(length))))
    case _: IO.print("usage")

def derive2(values: List<&2,List<&2,U32>>, hash: String, mode: String) -> IO(Unit):
  match values:
    case [a,b]:
      match mode:
        case "master": emit("master",P.master_secret(large(hash),a,b))
        case "client": emit("client",P.verify_data(large(hash),True{},a,b))
        case _: emit("server",P.verify_data(large(hash),False{},a,b))
    case _: IO.print("usage")

def protect_seal(chacha: String, high: String, low: String, kind: String, values: List<&2,List<&2,U32>>) -> IO(Unit):
  match values:
    case Con{key,Con{iv,records}}: seal_owner(seed_write(T.new12_write(String.eq(chacha,"1"),key,iv),number(high),number(low)),number(kind),records)
    case _: IO.print("usage")

def protect_open(chacha: String, high: String, low: String, kind: String, values: List<&2,List<&2,U32>>) -> IO(Unit):
  match values:
    case Con{key,Con{iv,records}}: open_owner(seed_read(T.new12_read(String.eq(chacha,"1"),key,iv),number(high),number(low)),number(kind),records)
    case _: IO.print("usage")

def derive.go(three: Bool, values: List<&2,List<&2,U32>>, hash: String, length: String, mode: String) -> IO(Unit):
  match three:
    case True{}: derive3(values,hash,length,mode)
    case False{}: derive2(values,hash,mode)

def derive(values: List<&2,List<&2,U32>>, hash: String, length: String, +mode: String) -> IO(Unit):
  derive.go(Bool.or(String.eq(mode,"prf"),String.eq(mode,"keys")),values,hash,length,mode)

# derive prf|keys hash length secret|master label|server seed|client
# derive master|client|server hash _ pms|master hash
# seal|open chacha(0|1) high low kind key iv records...
def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"derive",Con{mode,Con{hash,Con{length,paths}}}}:
      IO.bind(List<&2,List<&2,U32>>,Unit,read_files(paths),values => derive(values,hash,length,mode))
    case Con{"seal",Con{chacha,Con{high,Con{low,Con{kind,paths}}}}}:
      IO.bind(List<&2,List<&2,U32>>,Unit,read_files(paths),values => protect_seal(chacha,high,low,kind,values))
    case Con{"open",Con{chacha,Con{high,Con{low,Con{kind,paths}}}}}:
      IO.bind(List<&2,List<&2,U32>>,Unit,read_files(paths),values => protect_open(chacha,high,low,kind,values))
    case _: IO.die(Unit,2,"usage: derive MODE 256|384 LENGTH FILES... | seal|open 0|1 HIGH LOW KIND KEY IV RECORDS...")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
