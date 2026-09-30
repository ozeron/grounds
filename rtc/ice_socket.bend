import Base
import ./ice_transactions.bend as Tx
import ./stun_client.bend as Discovery
import ./ice_reliable.bend as Reliable
import ../wire/wire.bend as W

def Reply() -> Type:
  Socket & Tx.Step

def continue_failed(step: Tx.Step, socket: Socket, tail: List<&2, Tx.Notice>, reversed: List<&2, Tx.Notice>,
                    again: Socket -> Tx.State -> List<&2, Tx.Notice> -> List<&2, Tx.Notice> -> IO(Reply())) -> IO(Reply()):
  match step:
    case Tx.Step{changed, notices}:
      again(socket, changed, tail, List.reverse.go(&2, Tx.Notice, notices, reversed))

def continue_sent(result: Result<&1, &1, U32 & String, Unit>, socket: Socket, +state: Tx.State,
                  +token: U32, fresh: Bool, tail: List<&2, Tx.Notice>, reversed: List<&2, Tx.Notice>,
                  again: Socket -> Tx.State -> List<&2, Tx.Notice> -> List<&2, Tx.Notice> -> IO(Reply())) -> IO(Reply()):
  match result:
    case Done{_}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        again(socket, Tx.sent(state, now, fresh), tail, Con{Tx.Sent{token}, reversed})
    case Fail{(code, _)}:
      continue_failed(Tx.failed(state, token, code), socket, tail, reversed, again)

def sent(m: Discovery.RU(), state: Tx.State, token: U32, fresh: Bool, tail: List<&2, Tx.Notice>,
         reversed: List<&2, Tx.Notice>,
         again: Socket -> Tx.State -> List<&2, Tx.Notice> -> List<&2, Tx.Notice> -> IO(Reply())) -> IO(Reply()):
  (socket, result) = m
  continue_sent(result, socket, state, token, fresh, tail, reversed, again)

def execute_send(current: Bool, socket: Socket, state: Tx.State, notice: Tx.Notice, tail: List<&2, Tx.Notice>,
                 reversed: List<&2, Tx.Notice>, again: Socket -> Tx.State -> List<&2, Tx.Notice> -> List<&2, Tx.Notice> -> IO(Reply())) -> IO(Reply()):
  match current notice:
    case False{} _: again(socket, state, tail, reversed)
    case True{} Tx.Send{token, host, port, bytes, fresh}:
      IO.bind(Discovery.RU(), Reply(), W.wire_udp_send_to(socket, host, port, bytes, 1000),
        m => sent(m, state, token, fresh, tail, reversed, again))
    case True{} _: again(socket, state, tail, reversed)

def execute_go(fuel: Nat, socket: Socket, +state: Tx.State, notices: List<&2, Tx.Notice>,
               reversed: List<&2, Tx.Notice>) -> IO(Reply()):
  match fuel notices:
    case 0n _:
      IO.pure(Reply(), (socket, Tx.Step{state, List.reverse.go(&2, Tx.Notice, reversed, notices)}))
    case 1n+_ Nil{}:
      IO.pure(Reply(), (socket, Tx.Step{state, List.reverse(&2, Tx.Notice, reversed)}))
    case 1n+p Con{Tx.Send{+token, +host, +port, +bytes, +fresh}, tail}:
      execute_send(Tx.current_send(state, Tx.Send{token, host, port, bytes, fresh}), socket, state, Tx.Send{token, host, port, bytes, fresh}, tail, reversed,
        s => changed => rest => rev => execute_go(p, s, changed, rest, rev))
    case 1n+p Con{notice, tail}:
      execute_go(p, socket, state, tail, Con{notice, reversed})

def execute(socket: Socket, step: Tx.Step) -> IO(Reply()):
  match step:
    case Tx.Step{state, +notices}:
      execute_go(Nat.add(List.length(&2, Tx.Notice, notices), 1n), socket, state, notices, [])

def fail_all_go(entries: List<&2, Tx.Entry>, +code: U32, reversed: List<&2, Tx.Notice>) -> List<&2, Tx.Notice>:
  match entries:
    case Nil{}: List.reverse(&2, Tx.Notice, reversed)
    case Con{Tx.Entry{token, _, _, _, _}, tail}:
      fail_all_go(tail, code, Con{Tx.Finished{token, Reliable.TransportError{code}}, reversed})
    case Con{Tx.Listening{token, _, _}, tail}:
      fail_all_go(tail, code, Con{Tx.Retired{token}, reversed})

def fail_all(state: Tx.State, +code: U32) -> Tx.Step:
  match state:
    case Tx.State{entries, ta, capacity, next_start, next_send}:
      Tx.Step{Tx.State{[], ta, capacity, next_start, next_send},
        Con{Tx.SocketFailure{code}, fail_all_go(entries, code, [])}}

def recv_failed(oversize: Bool, socket: Socket, state: Tx.State, code: U32) -> IO(Reply()):
  match oversize:
    case True{}: IO.pure(Reply(), (socket, Tx.Step{state, []}))
    case False{}: IO.pure(Reply(), (socket, fail_all(state, code)))

def recv_result(result: Result<&1, &1, U32 & String, Maybe<&1, String & U32 & List<&2, U32>>>,
                socket: Socket, state: Tx.State) -> IO(Reply()):
  match result:
    case Done{Some{(host, (port, raw))}}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        return (socket, Tx.receive(state, host, port, raw, now))
    case Done{None{}}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        execute(socket, Tx.tick(state, now))
    case Fail{(+code, _)}:
      recv_failed(Bool.or(U32.is_eq(code, 40), U32.is_eq(code, 90)), socket, state, code)

def received(m: Discovery.RD(), state: Tx.State) -> IO(Reply()):
  (socket, result) = m
  recv_result(result, socket, state)

def polled(socket: Socket, +state: Tx.State, notices: List<&2, Tx.Notice>, cap: U32) -> IO(Reply()):
  match notices:
    case Con{notice, tail}:
      IO.pure(Reply(), (socket, Tx.Step{state, Con{notice, tail}}))
    case Nil{}:
      do IO<Reply()>:
        now : Nat <- IO.now()
        IO.bind(Discovery.RD(), Reply(), W.wire_udp_recv_from_timeout(socket, 65535, Tx.timeout(state, now, cap)),
          m => received(m, state))

def advanced(reply: Reply(), cap: U32) -> IO(Reply()):
  (socket, Tx.Step{state, notices}) = reply
  polled(socket, state, notices, cap)

# One bounded polling turn; the caller keeps socket and engine ownership and
# handles notices before the next turn. Raw datagrams are never authenticated
# merely by this dispatcher. Use the local credential server path to validate.
def poll(socket: Socket, +state: Tx.State, cap: U32) -> IO(Reply()):
  do IO<Reply()>:
    now : Nat <- IO.now()
    IO.bind(Reply(), Reply(), execute(socket, Tx.tick(state, now)), m => advanced(m, cap))
