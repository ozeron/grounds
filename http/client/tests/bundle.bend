import Base
import ../bend_transport.bend as Tr
import ../client.bend as C
import ../../../crypto/pem_bundle.bend as Bundle
import ../../../io/io.bend as Io

# Modes map to a constructor through String.eq; no string-literal match
# patterns (see http/client/BUILD_MEMORY.md).
type Mode is Data:
  MBytes{}
  MFile{}
  MSystemBytes{}
  MSystem{}
  MSystemEnv{}
  MUnknown{}

def pick_mode(hit: Bool, m: Mode, rest: Mode) -> Mode:
  match hit:
    case True{}: m
    case False{}: rest

def mode_of(+text: String) -> Mode:
  pick_mode(String.eq(text,"bytes"),MBytes{},pick_mode(String.eq(text,"file"),MFile{},pick_mode(String.eq(text,"system-bytes"),MSystemBytes{},pick_mode(String.eq(text,"system"),MSystem{},pick_mode(String.eq(text,"system-env"),MSystemEnv{},MUnknown{})))))

def counted(count: Nat, started: Nat) -> IO(Unit):
  do IO<Unit>:
    ended : Nat <- IO.now()
    IO.print("ok:" ++ Nat.show(count) ++ ":" ++ Nat.show(Nat.sub(ended,started)))

def prepared(value: C.R(Tr.Policy), started: Nat) -> IO(Unit):
  match value:
    case Done{Tr.Policy{_,_,roots,_}}: counted(List.length(&2,List<&2,U32>,roots),started)
    case Fail{C.Tls{reason}}: IO.print(reason)
    case Fail{_}: IO.print("unexpected-error")

def decoded(value: Result<&2,&2,Bundle.Error,List<&2,List<&2,U32>>>, started: Nat) -> IO(Unit):
  match value:
    case Done{roots}: counted(List.length(&2,List<&2,U32>,roots),started)
    case Fail{reason}: IO.print(Bundle.show(reason))

# ok:<anchors>:<ms>:<path>; the path is the bundle that was loaded.
def system(value: C.R(Tr.System), started: Nat) -> IO(Unit):
  match value:
    case Done{Tr.System{path,Tr.Policy{_,_,roots,_}}}:
      do IO<Unit>:
        ended : Nat <- IO.now()
        IO.print("ok:" ++ Nat.show(List.length(&2,List<&2,U32>,roots)) ++ ":" ++ Nat.show(Nat.sub(ended,started)) ++ ":" ++ path)
    case Fail{C.Tls{reason}}: IO.print(reason)
    case Fail{_}: IO.print("unexpected-error")

def load(mode: Mode, path: String, started: Nat) -> IO(Unit):
  match mode:
    case MFile{}:
      do IO<Unit>:
        value : C.R(Tr.Policy) <- Tr.from_bundle_file([],[],path,Tr.Clock{0n,0n})
        prepared(value,started)
    case MSystemBytes{}:
      do IO<Unit>:
        bytes : List<&2,U32> <- Io.read_bytes(path)
        at : Nat <- IO.now()
        decoded(Bundle.decode.system(bytes),at)
    case _:
      do IO<Unit>:
        bytes : List<&2,U32> <- Io.read_bytes(path)
        at : Nat <- IO.now()
        prepared(Tr.from_bundle([],[],bytes,Tr.Clock{0n,0n}),at)

def paths(+mode: Mode, args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit,Unit{})
    case Con{path,rest}:
      do IO<Unit>:
        started : Nat <- IO.now()
        load(mode,path,started)
        paths(mode,rest)

# system <SSL_CERT_FILE value or ""> <candidate>...: the explicit-list API.
def explicit(args: List<String>) -> IO(Unit):
  match args:
    case Con{override,candidates}:
      do IO<Unit>:
        started : Nat <- IO.now()
        value : C.R(Tr.System) <- Tr.from_system_bundle_paths([],[],Tr.system_candidates(override,candidates),Tr.Clock{0n,0n})
        system(value,started)
    case Nil{}: IO.die(Unit,2,"system override candidate...")

def ambient(u: Unit) -> IO(Unit):
  do IO<Unit>:
    started : Nat <- IO.now()
    value : C.R(Tr.System) <- Tr.from_system_bundle([],[],Tr.Clock{0n,0n})
    system(value,started)

def run(mode: Mode, rest: List<String>) -> IO(Unit):
  match mode:
    case MSystem{}: explicit(rest)
    case MSystemEnv{}: ambient(Unit{})
    case MUnknown{}: IO.die(Unit,2,"bytes|file|system-bytes bundle.pem ... | system override path... | system-env")
    case other: paths(other,rest)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{name,rest}: run(mode_of(name),rest)
    case _: IO.die(Unit,2,"bytes|file|system-bytes bundle.pem ... | system override path... | system-env")

def main() -> IO(Unit):
  IO.bind(List<String>,Unit,Io.args(),command)
