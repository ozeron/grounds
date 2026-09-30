import Base
import ./ice_candidates.bend as C
import ./ice_checklist.bend as Check
import ./stun.bend as Stun

# Operates on checklists from Check.build and their guarded state transitions.
# Transport identity does not depend on role, priority, foundation or list order.
# References belong to one ICE generation; its owner discards them on restart.
type Ref is Data:
  Ref{stream: U32, component: U32, base: Stun.IPv4, remote: Stun.IPv4}

type Position is Data:
  Position{stream: U32, index: Nat, pair: Check.CandidatePair}

type Search is Data:
  Search{count: Nat, position: Maybe<&2, Position>}

def reference(stream: U32, pair: Check.CandidatePair) -> Ref:
  match pair:
    case Check.CandidatePair{C.Local{_, C.Candidate{_, _, _, _, base}}, C.Candidate{component, _, _, _, remote}, _, _}:
      Ref{stream, component, base, remote}

def same(first: Ref, second: Ref) -> Bool:
  match first second:
    case Ref{a, b, c, d} Ref{w, x, y, z}:
      Bool.and(Bool.and(U32.is_eq(a, w), U32.is_eq(b, x)), Bool.and(C.address_same(c, y), C.address_same(d, z)))

def found(matches: Bool, search: Search, stream: U32, index: Nat, pair: Check.CandidatePair) -> Search:
  match matches search:
    case False{} s: s
    case True{} Search{n, _}: Search{Nat.add(n, 1n), Some{Position{stream, index, pair}}}

def find_pairs(pairs: List<&2, Check.CandidatePair>, +stream: U32, +wanted: Ref, +index: Nat, search: Search) -> Search:
  match pairs:
    case Nil{}: search
    case Con{+pair, tail}:
      find_pairs(tail, stream, wanted, Nat.add(index, 1n), found(same(reference(stream, pair), wanted), search, stream, index, pair))

def find_streams(streams: List<&2, Check.Checklist>, +wanted: Ref, search: Search) -> Search:
  match streams:
    case Nil{}: search
    case Con{Check.Checklist{id, pairs}, tail}:
      find_streams(tail, wanted, find_pairs(pairs, id, wanted, 0n, search))

def unique(search: Search) -> Maybe<&2, Position>:
  match search:
    case Search{1n, position}: position
    case _: None{}

# Reject both missing and ambiguous endpoints rather than targeting another pair.
def lookup(streams: List<&2, Check.Checklist>, wanted: Ref) -> Maybe<&2, Position>:
  unique(find_streams(streams, wanted, Search{0n, None{}}))

def begun(position: Maybe<&2, Position>, streams: List<&2, Check.Checklist>) -> Maybe<&2, List<&2, Check.Checklist>>:
  match position:
    case None{}: None{}
    case Some{Position{stream, index, _}}: Check.begin(streams, stream, index)

def begin(+streams: List<&2, Check.Checklist>, wanted: Ref) -> Maybe<&2, List<&2, Check.Checklist>>:
  begun(lookup(streams, wanted), streams)

def finished(position: Maybe<&2, Position>, streams: List<&2, Check.Checklist>, success: Bool) -> Maybe<&2, List<&2, Check.Checklist>>:
  match position:
    case None{}: None{}
    case Some{Position{stream, index, _}}: Check.finish_check(streams, stream, index, success)

def finish_check(+streams: List<&2, Check.Checklist>, wanted: Ref, success: Bool) -> Maybe<&2, List<&2, Check.Checklist>>:
  finished(lookup(streams, wanted), streams, success)

def ranked(rank: Maybe<&2, C.Priority>, local: C.Local, remote: C.Candidate, state: Check.PairState) -> Maybe<&2, Check.CandidatePair>:
  match rank:
    case None{}: None{}
    case Some{p}: Some{Check.CandidatePair{local, remote, p, state}}

def rerank(pair: Check.CandidatePair, controlling: Bool) -> Maybe<&2, Check.CandidatePair>:
  match pair:
    case Check.CandidatePair{C.Local{C.Candidate{+component, +priority, +foundation, +kind, +address}, +base},
                             C.Candidate{+rc, +rp, +rf, +rk, +ra}, _, state}:
      ranked(Bool.pick(Maybe<&2, C.Priority>, controlling, C.pair_priority(priority, rp), C.pair_priority(rp, priority)),
        C.Local{C.Candidate{component, priority, foundation, kind, address}, base}, C.Candidate{rc, rp, rf, rk, ra}, state)

def retained(pair: Maybe<&2, Check.CandidatePair>, +sorted: List<&2, Check.CandidatePair>,
             again: List<&2, Check.CandidatePair> -> Maybe<&2, List<&2, Check.CandidatePair>>) -> Maybe<&2, List<&2, Check.CandidatePair>>:
  match pair:
    case None{}: None{}
    case Some{p}: again(Check.insert(Nat.add(Check.length_pairs(sorted, 0n), 1n), sorted, p, []))

def reorder_pairs(fuel: Nat, pairs: List<&2, Check.CandidatePair>, +controlling: Bool,
                  sorted: List<&2, Check.CandidatePair>) -> Maybe<&2, List<&2, Check.CandidatePair>>:
  match fuel pairs:
    case 0n _: None{}
    case 1n+_ Nil{}: Some{sorted}
    case 1n+p Con{pair, tail}:
      retained(rerank(pair, controlling), sorted, acc => reorder_pairs(p, tail, controlling, acc))

def reordered(pairs: Maybe<&2, List<&2, Check.CandidatePair>>, stream: U32, reversed: List<&2, Check.Checklist>,
              again: List<&2, Check.Checklist> -> Maybe<&2, List<&2, Check.Checklist>>) -> Maybe<&2, List<&2, Check.Checklist>>:
  match pairs:
    case None{}: None{}
    case Some{ps}: again(Con{Check.Checklist{stream, ps}, reversed})

def reorder_streams(fuel: Nat, streams: List<&2, Check.Checklist>, +controlling: Bool,
                    reversed: List<&2, Check.Checklist>) -> Maybe<&2, List<&2, Check.Checklist>>:
  match fuel streams:
    case 0n _: None{}
    case 1n+_ Nil{}: Some{List.reverse(&2, Check.Checklist, reversed)}
    case 1n+p Con{Check.Checklist{id, +pairs}, tail}:
      reordered(reorder_pairs(Nat.add(Check.length_pairs(pairs, 0n), 1n), pairs, controlling, []), id, reversed,
        rev => reorder_streams(p, tail, controlling, rev))

# For checklists formed by Check.build. Preserve every pair's candidate metadata
# and state; recompute ranks from advertised priorities, never reflexive bases.
# No pruning, initial-state reset, queue mutation or nomination occurs here.
def reorder(+streams: List<&2, Check.Checklist>, controlling: Bool) -> Maybe<&2, List<&2, Check.Checklist>>:
  reorder_streams(Nat.add(List.length(&2, Check.Checklist, streams), 1n), streams, controlling, [])
