import Base
import ./tls_handshake_codec.bend as C
import ./tls_extensions.bend as E
import ./tls_extensions_cli.bend as D
import ./tls_hello_cli.bend as H
import ./tls_hello.bend as Hello
import ../crypto/bytes.bend as B
import ../io/io.bend as Io

def chain_summary(values: List<&2, List<&2, U32>>, text: String) -> String:
  match values:
    case Nil{}: text
    case Con{cert, rest}: chain_summary(rest, text ++ ":" ++ B.hex(cert))

def describe(value: C.Message) -> String:
  match value:
    case C.ClientHello{hello}: H.describe(hello)
    case C.ServerHello{hello}: H.describe(hello)
    case C.EncryptedExtensions{values}: "ee:" ++ D.flatten(values, [], 0n)
    case C.CertificateRequest{context, values}: "cr:" ++ B.hex(context) ++ ":" ++ D.flatten(values, [], 0n)
    case C.Certificate{context, values}: chain_summary(values, "cert:" ++ B.hex(context))
    case C.CertificateVerify{scheme, signature}: "cv:" ++ U32.show(scheme) ++ ":" ++ B.hex(signature)
    case C.Finished{data}: "finished:" ++ B.hex(data)
    case C.NewSessionTicket{}: "ticket"
    case C.KeyUpdate{request}: "update:" ++ U32.show(request)

def report(value: Result<&2, &2, U32, C.Message>) -> String:
  match value:
    case Fail{alert}: "error:" ++ U32.show(alert)
    case Done{message}: describe(message)

def report_alert(value: Result<&2, &2, U32, U32>) -> String:
  match value:
    case Fail{alert}: "error:" ++ U32.show(alert)
    case Done{description}: "alert:" ++ U32.show(description)

def maybe_bytes(value: Maybe<&2, List<&2, U32>>) -> String:
  match value:
    case None{}: "invalid"
    case Some{bytes}: B.hex(bytes)

def context_error(value: Maybe<&2, U32>) -> String:
  match value:
    case None{}: "valid"
    case Some{alert}: "error:" ++ U32.show(alert)

def context_checked(context: U32, value: Maybe<&2, List<&2, E.Extension>>) -> String:
  match value:
    case None{}: "error:50"
    case Some{extensions}: context_error(C.validate_extensions(context, [0, 5, 10, 13, 16, 18, 43, 50, 51, 65000], extensions))

def context_input(bytes: List<&2, U32>) -> String:
  match bytes:
    case Con{context, rest}: context_checked(context, E.parse(rest))
    case _: "error:50"

def encode_extensions(values: List<&2,E.Extension>) -> List<&2,U32>:
  match values:
    case Nil{}: []
    case Con{E.Extension{kind,body},rest}: B.append(C.extension(kind,body),encode_extensions(rest))

def encode_suites(values: List<&2,U32>) -> List<&2,U32>:
  match values:
    case Nil{}: []
    case Con{+suite,rest}: Con{U32.shrn(suite,8n),Con{U32.and(suite,255),encode_suites(rest)}}

def serialized(value: Result<&2, &2, U32, C.Message>) -> String:
  match value:
    case Fail{alert}: "error:" ++ U32.show(alert)
    case Done{C.ClientHello{Hello.Client{random,session,suites,extensions}}}: maybe_bytes(C.hello_client_suites(random,session,encode_suites(suites),encode_extensions(extensions)))
    case Done{C.ServerHello{Hello.Server{random,session,suite,extensions}}}: maybe_bytes(C.hello_server(random,session,suite,encode_extensions(extensions)))
    case Done{C.EncryptedExtensions{extensions}}: maybe_bytes(C.encrypted_extensions(encode_extensions(extensions)))
    case Done{C.CertificateRequest{context,extensions}}: maybe_bytes(C.certificate_request(context,encode_extensions(extensions)))
    case Done{C.Certificate{context, chain}}: maybe_bytes(C.certificate(context, chain))
    case Done{C.CertificateVerify{scheme, signature}}: maybe_bytes(C.certificate_verify(scheme, signature))
    case Done{C.Finished{data}}: maybe_bytes(C.finished(data))
    case Done{C.KeyUpdate{request}}: maybe_bytes(C.key_update(request))
    case Done{_}: "unsupported"

def serialize(bytes: List<&2, U32>) -> String:
  serialized(C.parse(bytes))

def evaluate(mode: String, bytes: List<&2, U32>) -> String:
  match mode:
    case "alerts": report_alert(C.parse_alert(bytes))
    case "contexts": context_input(bytes)
    case "serialize": serialize(bytes)
    case _: report(C.parse(bytes))

def loop(+mode: String, args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"nonbyte", rest}:
      do IO<Unit>:
        IO.print(evaluate(mode, [20, 0, 0, 1, 256]))
        loop(mode, rest)
    case Con{path, rest}:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        IO.print(evaluate(mode, bytes))
        loop(mode, rest)

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop("run", rest)
    case Con{"alerts", rest}: loop("alerts", rest)
    case Con{"contexts", rest}: loop("contexts", rest)
    case Con{"serialize", rest}: loop("serialize", rest)
    case _: IO.die(Unit, 2, "tls_handshake_codec_cli run|alerts|contexts|serialize <file> ...")

def args(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop("run", rest)
    case Con{"alerts", rest}: loop("alerts", rest)
    case Con{"contexts", rest}: loop("contexts", rest)
    case Con{"serialize", rest}: loop("serialize", rest)
    case Con{_, rest}: command(rest)
    case _: command([])

def main() -> IO(Unit):
  do IO<Unit>:
    values : List<String> <- Io.args()
    args(values)
