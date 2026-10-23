import Base
import ./tls_server_handshake.bend as S
import ../crypto/bytes.bend as B
import ../io/io.bend as Io

def describe(value: Result<&2,&2,U32,S.Choice>) -> String:
  match value:
    case Fail{code}: "error:" ++ U32.show(code)
    case Done{S.Choice{suite,group,share,sni,alpn}}:
      "ok:" ++ U32.show(suite) ++ ":" ++ U32.show(group) ++ ":" ++ B.hex(share) ++ ":" ++ B.hex(sni) ++ ":" ++ Bool.pick(String,alpn,"true","false")

def loop(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit,Unit{})
    case Con{path,rest}:
      do IO<Unit>:
        bytes : List<&2,U32> <- Io.read_bytes(path)
        IO.print(describe(S.negotiate(S.Policy{[4865,4867],[29,23],True{}},1027,bytes)))
        loop(rest)

def retry_loop(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit,Unit{})
    case Con{first,Con{second,Con{cookie,rest}}}:
      do IO<Unit>:
        a : List<&2,U32> <- Io.read_bytes(first)
        b : List<&2,U32> <- Io.read_bytes(second)
        c : List<&2,U32> <- Io.read_bytes(cookie)
        IO.print(Bool.pick(String,S.retry_valid(a,b,c,23),"retry:true","retry:false"))
        retry_loop(rest)
    case _: IO.die(Unit,2,"retry first second cookie ...")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Con{"retry",rest}: retry_loop(rest)
    case args: loop(args)

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
