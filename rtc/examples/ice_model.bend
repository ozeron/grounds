import Base
import ../ice_candidates.bend as C
import ../ice_checklist.bend as Check
import ../stun.bend as Stun
import ../../json/json.bend as J
import ../../io/io.bend as Io

# JSON is a fixture adapter, not ICE signaling. Positional candidate fields are
# [component, priority, foundation, flavor, [IPv4 octets, port]].
def address_numbers(a: Result<&2, &2, J.Access, U32>, b: Result<&2, &2, J.Access, U32>,
                    c: Result<&2, &2, J.Access, U32>, d: Result<&2, &2, J.Access, U32>,
                    p: Result<&2, &2, J.Access, U32>) -> Maybe<&2, Stun.IPv4>:
  match a b c d p:
    case Done{a} Done{b} Done{c} Done{d} Done{p}: Some{Stun.IPv4{a, b, c, d, p}}
    case _ _ _ _ _: None{}

def address(value: J.Json) -> Maybe<&2, Stun.IPv4>:
  match value:
    case J.JArr{[a, b, c, d, port]}: address_numbers(J.u32(a), J.u32(b), J.u32(c), J.u32(d), J.u32(port))
    case _: None{}

def flavor(value: String) -> Maybe<&2, C.Flavor>:
  match value:
    case "host": Some{C.Host{}}
    case "srflx": Some{C.ServerReflexive{}}
    case "prflx": Some{C.PeerReflexive{}}
    case "relay": Some{C.Relay{}}
    case _: None{}

def candidate_parts(component: Result<&2, &2, J.Access, U32>, priority: Result<&2, &2, J.Access, U32>,
                    foundation: String, kind: Maybe<&2, C.Flavor>, address: Maybe<&2, Stun.IPv4>) -> Maybe<&2, C.Candidate>:
  match component priority kind address:
    case Done{c} Done{p} Some{k} Some{a}: Some{C.Candidate{c, p, foundation, k, a}}
    case _ _ _ _: None{}

def candidate(value: J.Json) -> Maybe<&2, C.Candidate>:
  match value:
    case J.JArr{[component, priority, J.JStr{foundation}, J.JStr{kind}, addr]}:
      candidate_parts(J.u32(component), J.u32(priority), foundation, flavor(kind), address(addr))
    case _: None{}

def local_parts(a: Maybe<&2, C.Candidate>, b: Maybe<&2, C.Candidate>) -> Maybe<&2, C.Local>:
  match a b:
    case Some{a} Some{b}: Some{C.Local{a, b}}
    case _ _: None{}

def local(value: J.Json) -> Maybe<&2, C.Local>:
  match value:
    case J.JArr{[a, b]}: local_parts(candidate(a), candidate(b))
    case _: None{}

def remote_parsed(value: Maybe<&2, C.Candidate>, reversed: List<&2, C.Candidate>,
                  again: List<&2, C.Candidate> -> Maybe<&2, List<&2, C.Candidate>>) -> Maybe<&2, List<&2, C.Candidate>>:
  match value:
    case None{}: None{}
    case Some{c}: again(Con{c, reversed})

def remotes(fuel: Nat, values: List<&2, J.Json>, reversed: List<&2, C.Candidate>) -> Maybe<&2, List<&2, C.Candidate>>:
  match fuel values:
    case 0n _: None{}
    case 1n+_ Nil{}: Some{List.reverse(&2, C.Candidate, reversed)}
    case 1n+p Con{value, tail}: remote_parsed(candidate(value), reversed, rev => remotes(p, tail, rev))

def local_parsed(value: Maybe<&2, C.Local>, reversed: List<&2, C.Local>,
                 again: List<&2, C.Local> -> Maybe<&2, List<&2, C.Local>>) -> Maybe<&2, List<&2, C.Local>>:
  match value:
    case None{}: None{}
    case Some{c}: again(Con{c, reversed})

def locals(fuel: Nat, values: List<&2, J.Json>, reversed: List<&2, C.Local>) -> Maybe<&2, List<&2, C.Local>>:
  match fuel values:
    case 0n _: None{}
    case 1n+_ Nil{}: Some{List.reverse(&2, C.Local, reversed)}
    case 1n+p Con{value, tail}: local_parsed(local(value), reversed, rev => locals(p, tail, rev))

def stream_parts(id: Result<&2, &2, J.Access, U32>, locals: Maybe<&2, List<&2, C.Local>>,
                 remotes: Maybe<&2, List<&2, C.Candidate>>) -> Maybe<&2, Check.Stream>:
  match id locals remotes:
    case Done{id} Some{ls} Some{rs}: Some{Check.Stream{id, ls, rs}}
    case _ _ _: None{}

def stream(value: J.Json) -> Maybe<&2, Check.Stream>:
  match value:
    case J.JArr{[id, J.JArr{ls}, J.JArr{rs}]}: stream_parts(J.u32(id), locals(66n, ls, []), remotes(66n, rs, []))
    case _: None{}

def stream_parsed(value: Maybe<&2, Check.Stream>, reversed: List<&2, Check.Stream>,
                  again: List<&2, Check.Stream> -> Maybe<&2, List<&2, Check.Stream>>) -> Maybe<&2, List<&2, Check.Stream>>:
  match value:
    case None{}: None{}
    case Some{s}: again(Con{s, reversed})

def streams(fuel: Nat, values: List<&2, J.Json>, reversed: List<&2, Check.Stream>) -> Maybe<&2, List<&2, Check.Stream>>:
  match fuel values:
    case 0n _: None{}
    case 1n+_ Nil{}: Some{List.reverse(&2, Check.Stream, reversed)}
    case 1n+p Con{value, tail}: stream_parsed(stream(value), reversed, rev => streams(p, tail, rev))

def pair_text(pair: Check.CandidatePair) -> String:
  match pair:
    case Check.CandidatePair{C.Local{C.Candidate{component, original, _, _, _},
      C.Candidate{_, base_priority, local_f, _, +base}}, C.Candidate{_, remote_priority, remote_f, _, +remote},
      C.Priority{high, low}, state}:
      "pair:" ++ U32.show(component) ++ ":" ++ U32.show(original) ++ ":" ++ U32.show(base_priority) ++ ":" ++
      C.host(base) ++ "/" ++ U32.show(C.port(base)) ++ ":" ++ U32.show(remote_priority) ++ ":" ++
      C.host(remote) ++ "/" ++ U32.show(C.port(remote)) ++ ":" ++ local_f ++ ":" ++ remote_f ++ ":" ++
      U32.show(high) ++ ":" ++ U32.show(low) ++ ":" ++ U32.show(Check.state_code(state))

def show_pairs(pairs: List<&2, Check.CandidatePair>) -> IO(Unit):
  match pairs:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{pair, tail}:
      do IO<Unit>:
        x : Unit <- IO.print(pair_text(pair))
        show_pairs(tail)

def show_lists(checklists: List<&2, Check.Checklist>) -> IO(Unit):
  match checklists:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{Check.Checklist{id, pairs}, tail}:
      do IO<Unit>:
        x : Unit <- IO.print("stream:" ++ U32.show(id))
        y : Unit <- show_pairs(pairs)
        show_lists(tail)

def show(result: Maybe<&2, List<&2, Check.Checklist>>) -> IO(Unit):
  match result:
    case None{}: IO.print("invalid")
    case Some{lists}: show_lists(lists)

def action(name: String, lists: List<&2, Check.Checklist>, id: U32, index: U32) -> Maybe<&2, List<&2, Check.Checklist>>:
  match name:
    case "begin": Check.begin(lists, id, U32.to_nat(index))
    case "success": Check.finish_check(lists, id, U32.to_nat(index), True{})
    case "failure": Check.finish_check(lists, id, U32.to_nat(index), False{})
    case _: None{}

def action_numbers(name: String, lists: List<&2, Check.Checklist>, id: Result<&2, &2, J.Access, U32>, index: Result<&2, &2, J.Access, U32>) -> Maybe<&2, List<&2, Check.Checklist>>:
  match id index:
    case Done{id} Done{index}: action(name, lists, id, index)
    case _ _: None{}

def actions(fuel: Nat, values: List<&2, J.Json>, result: Maybe<&2, List<&2, Check.Checklist>>) -> IO(Unit):
  match fuel values result:
    case _ _ None{}: IO.print("invalid")
    case 0n _ _: IO.print("invalid")
    case 1n+_ Nil{} Some{lists}: show_lists(lists)
    case 1n+p Con{J.JArr{[J.JStr{name}, id, index]}, tail} Some{lists}:
      actions(p, tail, action_numbers(name, lists, J.u32(id), J.u32(index)))
    case _ _ _: IO.print("invalid")

def built(streams: Maybe<&2, List<&2, Check.Stream>>, controlling: Bool, limit: Result<&2, &2, J.Access, U32>, steps: List<&2, J.Json>) -> IO(Unit):
  match streams limit:
    case Some{values} Done{cap}: actions(1024n, steps, Check.build(values, controlling, cap))
    case _ _: IO.print("invalid")

def priority_show(priority: Maybe<&2, U32>) -> IO(Unit):
  match priority:
    case None{}: IO.print("invalid")
    case Some{p}: IO.print(U32.show(p))

def priority_numbers(a: Result<&2, &2, J.Access, U32>, b: Result<&2, &2, J.Access, U32>, c: Result<&2, &2, J.Access, U32>) -> IO(Unit):
  match a b c:
    case Done{a} Done{b} Done{c}: priority_show(C.candidate_priority(a, b, c))
    case _ _ _: IO.print("invalid")

def pair_show(priority: Maybe<&2, C.Priority>) -> IO(Unit):
  match priority:
    case None{}: IO.print("invalid")
    case Some{C.Priority{h, l}}: IO.print(U32.show(h) ++ ":" ++ U32.show(l))

def pair_numbers(a: Result<&2, &2, J.Access, U32>, b: Result<&2, &2, J.Access, U32>) -> IO(Unit):
  match a b:
    case Done{a} Done{b}: pair_show(C.pair_priority(a, b))
    case _ _: IO.print("invalid")

def priorities(values: List<&2, J.Json>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{J.JArr{[a, b, c]}, tail}:
      do IO<Unit>:
        x : Unit <- priority_numbers(J.u32(a), J.u32(b), J.u32(c))
        priorities(tail)
    case _: IO.print("invalid")

def pair_priorities(values: List<&2, J.Json>) -> IO(Unit):
  match values:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{J.JArr{[a, b]}, tail}:
      do IO<Unit>:
        x : Unit <- pair_numbers(J.u32(a), J.u32(b))
        pair_priorities(tail)
    case _: IO.print("invalid")

def decoded(result: Result<&2, &2, J.Error, J.Json>) -> IO(Unit):
  match result:
    case Done{J.JArr{[J.JStr{"checklists"}, J.JBool{control}, limit, J.JArr{values}, J.JArr{steps}]}}:
      built(streams(18n, values, []), control, J.u32(limit), steps)
    case Done{J.JArr{[J.JStr{"priorities"}, J.JArr{values}]}}: priorities(values)
    case Done{J.JArr{[J.JStr{"pair-priorities"}, J.JArr{values}]}}: pair_priorities(values)
    case _: IO.print("invalid")

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [path]:
      do IO<Unit>:
        bytes : List<&2, U32> <- Io.read_bytes(path)
        decoded(J.parse_bytes(bytes))
    case _: IO.die(Unit, 2, "usage: ice_model <fixture.json>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
