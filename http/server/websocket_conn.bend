import Base
import ../../wire/wire.bend as W
import ../wire/bytes.bend as B
import ../../utf8/utf8.bend as U
import ./websocket_frame.bend as F

# A WebSocket session owns its socket after the HTTP 101. A handler receives
# complete text or binary messages and may answer with one message.
type Message is Data:
  Message{opcode: U32, payload: B.Bytes}

type Parts is Data:
  Idle{}
  Fragment{opcode: U32, reversed: B.Bytes, size: Nat}

def RP() -> Type:
  Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>

def RU() -> Type:
  Socket & Result<&1, &1, U32 & String, Unit>

def code_bytes(+code: U32) -> B.Bytes:
  B.BCon{U32.shrn(code, 8n), B.BCon{U32.and(code, 255), B.BNil{}}}

def sent_close(m: RU()) -> IO(Unit):
  (s, _) = m
  W.wire_close(s)

def close_frame(s: Socket, +ms: U32, payload: B.Bytes) -> IO(Unit):
  IO.bind(RU(), Unit, W.wire_send_timeout(s, B.to_list(F.write(8, payload)), ms), m => sent_close(m))

def fail(s: Socket, +ms: U32, +code: U32) -> IO(Unit):
  close_frame(s, ms, code_bytes(code))

def text_ok(decoded: U.Text) -> Bool:
  match decoded:
    case U.TOk{_}:
      True{}
    case U.TBad{_, _}:
      False{}

def payload_ok(+op: U32, +payload: B.Bytes) -> Bool:
  Bool.or(U32.is_eq(op, 2), Bool.and(U32.is_eq(op, 1), text_ok(U.decode(B.to_list(payload)))))

def close_code(+code: U32) -> Bool:
  Bool.or(Bool.and(U32.is_ge(code, 1000), Bool.and(U32.is_le(code, 1014),
    Bool.and(Bool.not(U32.is_eq(code, 1004)), Bool.and(Bool.not(U32.is_eq(code, 1005)),
      Bool.and(Bool.not(U32.is_eq(code, 1006)), Bool.not(U32.is_eq(code, 1015))))))),
    U32.is_ge(code, 3000))

def close_payload.tail(bs: B.Bytes, +code: U32) -> Bool:
  Bool.and(close_code(code), text_ok(U.decode(B.to_list(bs))))

def close_payload(bs: B.Bytes) -> Bool:
  match bs:
    case B.BNil{}:
      True{}
    case B.BCon{_, B.BNil{}}:
      False{}
    case B.BCon{+hi, B.BCon{+lo, tail}}:
      close_payload.tail(tail, (hi * 256 + lo : U32))

def Next() -> Type:
  Socket -> B.Bytes -> Parts -> IO(Unit)

def sent(next: Next(), acc: B.Bytes, parts: Parts, m: RU()) -> IO(Unit):
  match m:
    case (s, Done{_}):
      next(s, acc, parts)
    case (s, Fail{_}):
      W.wire_close(s)

def send(next: Next(), s: Socket, acc: B.Bytes, parts: Parts, +ms: U32,
         +op: U32, payload: B.Bytes) -> IO(Unit):
  IO.bind(RU(), Unit, W.wire_send_timeout(s, B.to_list(F.write(op, payload)), ms),
    m => sent(next, acc, parts, m))

def replied(ok: Bool, next: Next(), s: Socket, acc: B.Bytes, +ms: U32,
            +op: U32, payload: B.Bytes) -> IO(Unit):
  match ok:
    case True{}:
      send(next, s, acc, Idle{}, ms, op, payload)
    case False{}:
      fail(s, ms, 1007)

def answer.message(+op: U32, +payload: B.Bytes, next: Next(), s: Socket,
                   acc: B.Bytes, +ms: U32) -> IO(Unit):
  replied(Bool.and(payload_ok(op, payload),
    Nat.is_le(F.size(payload, 0n), 1048576n)), next, s, acc, ms, op, payload)

def answer(reply: Maybe<&2, Message>, next: Next(), s: Socket,
           acc: B.Bytes, +ms: U32) -> IO(Unit):
  match reply:
    case None{}:
      next(s, acc, Idle{})
    case Some{Message{op, payload}}:
      answer.message(op, payload, next, s, acc, ms)

def delivered(ok: Bool, h: Message -> IO(Maybe<&2, Message>), next: Next(),
              s: Socket, acc: B.Bytes, +ms: U32, +op: U32, payload: B.Bytes) -> IO(Unit):
  match ok:
    case True{}:
      IO.bind(Maybe<&2, Message>, Unit, h(Message{op, payload}),
        reply => answer(reply, next, s, acc, ms))
    case False{}:
      fail(s, ms, 1007)

def deliver(h: Message -> IO(Maybe<&2, Message>), next: Next(), s: Socket,
            acc: B.Bytes, +ms: U32, +op: U32, +payload: B.Bytes) -> IO(Unit):
  delivered(payload_ok(op, payload), h, next, s, acc, ms, op, payload)

def continuation.ok(ok: Bool, fin: Bool, h: Message -> IO(Maybe<&2, Message>),
                    next: Next(), s: Socket, acc: B.Bytes, +ms: U32, +op: U32,
                    reversed: B.Bytes, +size: Nat, +payload: B.Bytes) -> IO(Unit):
  match ok fin:
    case False{} _:
      fail(s, ms, 1009)
    case True{} True{}:
      deliver(h, next, s, acc, ms, op, B.rev(B.rev.go(payload, reversed)))
    case True{} False{}:
      next(s, acc, Fragment{op, B.rev.go(payload, reversed),
        Nat.add(size, F.size(payload, 0n))})

def continuation(fin: Bool, h: Message -> IO(Maybe<&2, Message>), next: Next(),
                 s: Socket, acc: B.Bytes, +ms: U32, +op: U32, reversed: B.Bytes,
                 +size: Nat, +payload: B.Bytes) -> IO(Unit):
  continuation.ok(Nat.is_le(Nat.add(size, F.size(payload, 0n)), 1048576n),
    fin, h, next, s, acc, ms, op, reversed, size, payload)

def start(fin: Bool, h: Message -> IO(Maybe<&2, Message>), next: Next(), s: Socket,
          acc: B.Bytes, +ms: U32, +op: U32, +payload: B.Bytes) -> IO(Unit):
  match fin:
    case True{}:
      deliver(h, next, s, acc, ms, op, payload)
    case False{}:
      next(s, acc, Fragment{op, B.rev(payload), F.size(payload, 0n)})

def data.idle(op: U32, fin: Bool, h: Message -> IO(Maybe<&2, Message>), next: Next(),
              s: Socket, acc: B.Bytes, +ms: U32, payload: B.Bytes) -> IO(Unit):
  match op:
    case 0:
      fail(s, ms, 1002)
    case +kind:
      start(fin, h, next, s, acc, ms, kind, payload)

def data.fragment(op: U32, fin: Bool, h: Message -> IO(Maybe<&2, Message>), next: Next(),
                  s: Socket, acc: B.Bytes, +ms: U32, +kind: U32, reversed: B.Bytes,
                  +size: Nat, payload: B.Bytes) -> IO(Unit):
  match op:
    case 0:
      continuation(fin, h, next, s, acc, ms, kind, reversed, size, payload)
    case _:
      fail(s, ms, 1002)

def data(op: U32, fin: Bool, h: Message -> IO(Maybe<&2, Message>), next: Next(),
         s: Socket, acc: B.Bytes, parts: Parts, +ms: U32, payload: B.Bytes) -> IO(Unit):
  match parts:
    case Idle{}:
      data.idle(op, fin, h, next, s, acc, ms, payload)
    case Fragment{kind, reversed, +size}:
      data.fragment(op, fin, h, next, s, acc, ms, kind, reversed, size, payload)

def close_received(valid: Bool, s: Socket, +ms: U32, payload: B.Bytes) -> IO(Unit):
  match valid:
    case True{}:
      close_frame(s, ms, payload)
    case False{}:
      fail(s, ms, 1002)

def frame(h: Message -> IO(Maybe<&2, Message>), next: Next(), s: Socket,
          acc: B.Bytes, parts: Parts, +ms: U32, fin: Bool, +op: U32,
          +payload: B.Bytes) -> IO(Unit):
  match op:
    case 8:
      close_received(close_payload(payload), s, ms, payload)
    case 9:
      send(next, s, acc, parts, ms, 10, payload)
    case 10:
      next(s, acc, parts)
    case other:
      data(other, fin, h, next, s, acc, parts, ms, payload)

def received(r: Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>,
             next: Next(), s: Socket,
             acc: B.Bytes, parts: Parts, +ms: U32) -> IO(Unit):
  match r:
    case Done{Some{Con{byte, tail}}}:
      next(s, B.app(acc, B.of_list(Con{byte, tail})), parts)
    case _:
      W.wire_close(s)

def polled(next: Next(), acc: B.Bytes,
           parts: Parts, +ms: U32, m: RP()) -> IO(Unit):
  (s, r) = m
  received(r, next, s, acc, parts, ms)

def parsed(p: F.Parsed, h: Message -> IO(Maybe<&2, Message>), next: Next(),
           s: Socket, acc: B.Bytes, parts: Parts, +ms: U32) -> IO(Unit):
  match p:
    case F.More{}:
      IO.bind(RP(), Unit, W.wire_recv_timeout(s, 65536, ms),
        m => polled(next, acc, parts, ms, m))
    case F.Bad{+code}:
      fail(s, ms, code)
    case F.Frame{fin, +opcode, payload, rest}:
      frame(h, next, s, rest, parts, ms, fin, opcode, payload)

def loop(~h: Message -> IO(Maybe<&2, Message>), fuel: Nat, s: Socket,
         +acc: B.Bytes, parts: Parts, +ms: U32) -> IO(Unit):
  match fuel:
    case 0n:
      fail(s, ms, 1001)
    case 1n+p:
      parsed(F.parse(acc), h, sk => buf => ps => loop(~h, p, sk, buf, ps, ms),
        s, acc, parts, ms)

def session(~h: Message -> IO(Maybe<&2, Message>), +ms: U32,
            s: Socket, initial: B.Bytes) -> IO(Unit):
  loop(~h, 4294967295n, s, initial, Idle{}, ms)
