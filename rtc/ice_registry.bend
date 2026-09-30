import Base
import ./ice_checklist.bend as Check
import ./ice_candidates.bend as C
import ./ice_pairs.bend as Pairs
import ./stun.bend as Stun

# Keep signaled candidates even when checklist pruning keeps no associated pair.
type State is Data:
  State{streams: List<&2, Check.Stream>, next: Nat, learned: Nat, limit: U32}

type BaseMatch is Data:
  BaseMatch{candidate: Maybe<&2, C.Candidate>, consistent: Bool}

type Learned is Data:
  Learned{registry: State, candidate: C.Candidate}

def base_match(matches: BaseMatch, +base: C.Candidate) -> BaseMatch:
  match matches:
    case BaseMatch{None{}, ok}: BaseMatch{Some{base}, ok}
    case BaseMatch{Some{+old}, ok}: BaseMatch{Some{old}, Bool.and(ok, C.same(old, base))}

def base_matches(locals: List<&2, C.Local>, +component: U32, +address: Stun.IPv4, +found: BaseMatch) -> BaseMatch:
  match locals:
    case Nil{}: found
    case Con{C.Local{_, C.Candidate{+c, +p, +f, +k, +a}}, tail}:
      base_matches(tail, component, address, Bool.pick(BaseMatch, Bool.and(U32.is_eq(component, c), C.address_same(address, a)),
        base_match(found, C.Candidate{c, p, f, k, a}), found))

def base_result(found: BaseMatch) -> Maybe<&2, C.Local>:
  match found:
    case BaseMatch{Some{+c}, True{}}: Some{C.Local{c, c}}
    case _: None{}

def local(streams: List<&2, Check.Stream>, +id: U32, +component: U32, +address: Stun.IPv4) -> Maybe<&2, C.Local>:
  match streams:
    case Nil{}: None{}
    case Con{Check.Stream{got, ls, _}, tail}:
      Bool.pick(Maybe<&2, C.Local>, U32.is_eq(id, got), base_result(base_matches(ls, component, address, BaseMatch{None{}, True{}})), local(tail, id, component, address))

def remote_candidates(values: List<&2, C.Candidate>, +component: U32, +address: Stun.IPv4) -> Maybe<&2, C.Candidate>:
  match values:
    case Nil{}: None{}
    case Con{C.Candidate{+c, +p, +f, +k, +a}, tail}:
      Bool.pick(Maybe<&2, C.Candidate>, Bool.and(U32.is_eq(c, component), C.address_same(a, address)),
        Some{C.Candidate{c, p, f, k, a}}, remote_candidates(tail, component, address))

def remote(streams: List<&2, Check.Stream>, +id: U32, +component: U32, +address: Stun.IPv4) -> Maybe<&2, C.Candidate>:
  match streams:
    case Nil{}: None{}
    case Con{Check.Stream{got, _, rs}, tail}:
      Bool.pick(Maybe<&2, C.Candidate>, U32.is_eq(id, got), remote_candidates(rs, component, address), remote(tail, id, component, address))

def remote_unique(values: List<&2, C.Candidate>, ok: Bool) -> Bool:
  match values:
    case Nil{}: ok
    case Con{C.Candidate{c, _, _, _, a}, +tail}:
      remote_unique(tail, Bool.and(ok, Bool.not(Maybe.is_some(&2, C.Candidate, remote_candidates(tail, c, a)))))

def bases_valid(values: List<&2, C.Local>, +ls: List<&2, C.Local>, ok: Bool) -> Bool:
  match values:
    case Nil{}: ok
    case Con{C.Local{_, C.Candidate{c, _, _, _, a}}, tail}:
      bases_valid(tail, ls, Bool.and(ok, Maybe.is_some(&2, C.Local, base_result(base_matches(ls, c, a, BaseMatch{None{}, True{}})))))

def valid(streams: List<&2, Check.Stream>, ok: Bool) -> Bool:
  match streams:
    case Nil{}: ok
    case Con{Check.Stream{_, +ls, rs}, tail}: valid(tail, Bool.and(ok, Bool.and(bases_valid(ls, ls, True{}), remote_unique(rs, True{}))))

def foundation_candidates(values: List<&2, C.Candidate>, +wanted: String, found: Bool) -> Bool:
  match values:
    case Nil{}: found
    case Con{C.Candidate{_, _, f, _, _}, tail}: foundation_candidates(tail, wanted, Bool.or(found, String.eq(f, wanted)))

def foundation_exists(streams: List<&2, Check.Stream>, +wanted: String, found: Bool) -> Bool:
  match streams:
    case Nil{}: found
    case Con{Check.Stream{_, _, rs}, tail}: foundation_exists(tail, wanted, foundation_candidates(rs, wanted, found))

def added(streams: List<&2, Check.Stream>, +id: U32, +candidate: C.Candidate, rev: List<&2, Check.Stream>) -> List<&2, Check.Stream>:
  match streams:
    case Nil{}: List.reverse(&2, Check.Stream, rev)
    case Con{Check.Stream{+got, ls, +rs}, tail}:
      added(tail, id, candidate, Con{Check.Stream{got, ls, Bool.pick(List<&2, C.Candidate>, U32.is_eq(got, id), Con{candidate, rs}, rs)}, rev})

def named(ok: Bool, +state: State, id: U32, +component: U32, +priority: U32, +source: Stun.IPv4,
          +name: String, +next: Nat, again: Nat -> Maybe<&2, Learned>) -> Maybe<&2, Learned>:
  match ok state:
    case False{} _: None{}
    case True{} State{+streams, _, count, limit}:
      Bool.pick(Maybe<&2, Learned>, foundation_exists(streams, name, False{}), again(Nat.add(next, 1n)),
        Some{Learned{State{added(streams, id, C.Candidate{component, priority, name, C.PeerReflexive{}, source}, []), Nat.add(next, 1n), Nat.add(count, 1n), limit},
          C.Candidate{component, priority, name, C.PeerReflexive{}, source}}})

def name_go(fuel: Nat, +state: State, +id: U32, +component: U32, +priority: U32, +source: Stun.IPv4, +next: Nat) -> Maybe<&2, Learned>:
  match fuel:
    case 0n: None{}
    case 1n+p:
      named(Nat.is_le(next, 4294967295n), state, id, component, priority, source, "p" ++ Nat.show(next), next,
        n => name_go(p, state, id, component, priority, source, n))

def learned(existing: Maybe<&2, C.Candidate>, state: State, +id: U32, +component: U32, +priority: U32, +source: Stun.IPv4) -> Maybe<&2, Learned>:
  match existing state:
    case Some{c} s: Some{Learned{s, c}}
    case None{} State{+streams, +next, +count, +limit}:
      Bool.pick(Maybe<&2, Learned>, Bool.and(Nat.is_lt(count, U32.to_nat(limit)),
        C.valid(C.Candidate{component, priority, "p", C.PeerReflexive{}, source})),
        name_go(1281n, State{streams, next, count, limit}, id, component, priority, source, next), None{})

# Only the session layer calls this after local-base and credential binding.
def learn(+state: State, +id: U32, +component: U32, priority: U32, +source: Stun.IPv4) -> Maybe<&2, Learned>:
  match state:
    case State{+streams, +next, +count, +limit}:
      learned(remote(streams, id, component, source), State{streams, next, count, limit}, id, component, priority, source)

def priority(local: C.Local) -> Maybe<&2, U32>:
  match local:
    case C.Local{_, C.Candidate{component, p, _, _, _}}:
      C.candidate_priority(110, U32.shrn(U32.and(p, 16776960), 8n), component)
