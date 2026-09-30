import Base
import ./ice_candidates.bend as C

# UDP/IPv4 formation and check-state bookkeeping. A successful check is not
# nomination: valid-pair construction and nominated checklist completion follow.
type PairState is Data:
  Frozen{}
  Waiting{}
  InProgress{}
  Succeeded{}
  Failed{}

type CandidatePair is Data:
  CandidatePair{source: C.Local, remote: C.Candidate, priority: C.Priority, state: PairState}

type Stream is Data:
  Stream{id: U32, locals: List<&2, C.Local>, remotes: List<&2, C.Candidate>}

type Checklist is Data:
  Checklist{id: U32, pairs: List<&2, CandidatePair>}

type Quota is Data:
  Quota{id: U32, pairs: List<&2, CandidatePair>, count: Nat}

def length_pairs(pairs: List<&2, CandidatePair>, +n: Nat) -> Nat:
  match pairs:
    case Nil{}: n
    case Con{_, tail}: length_pairs(tail, Nat.add(n, 1n))

def component(pair: CandidatePair) -> U32:
  match pair:
    case CandidatePair{_, C.Candidate{component, _, _, _, _}, _, _}: component

def candidate_foundation(candidate: C.Candidate, remote: String) -> String & String:
  match candidate:
    case C.Candidate{_, _, local, _, _}: (local, remote)

def foundation(pair: CandidatePair) -> String & String:
  match pair:
    case CandidatePair{source, C.Candidate{_, _, remote, _, _}, _, _}:
      candidate_foundation(C.check_candidate(source), remote)

def foundations_equal(first: String & String, second: String & String) -> Bool:
  (a, b) = first
  (c, d) = second
  Bool.and(String.eq(a, c), String.eq(b, d))

def foundation_same(first: CandidatePair, second: CandidatePair) -> Bool:
  foundations_equal(foundation(first), foundation(second))

def redundant(first: CandidatePair, second: CandidatePair) -> Bool:
  match first second:
    case CandidatePair{C.Local{_, C.Candidate{_, _, _, _, a}}, remote_a, _, _}
         CandidatePair{C.Local{_, C.Candidate{_, _, _, _, b}}, remote_b, _, _}:
      Bool.and(C.address_same(a, b), C.same(remote_a, remote_b))

def higher(first: CandidatePair, second: CandidatePair) -> Bool:
  match first second:
    case CandidatePair{_, _, a, _} CandidatePair{_, _, b, _}: C.greater(a, b)

def restate(pair: CandidatePair, state: PairState) -> CandidatePair:
  match pair:
    case CandidatePair{local, remote, priority, _}: CandidatePair{local, remote, priority, state}

def dominates(pairs: List<&2, CandidatePair>, +pair: CandidatePair, found: Bool) -> Bool:
  match pairs:
    case Nil{}: found
    case Con{+other, tail}:
      dominates(tail, pair, Bool.or(found, Bool.and(redundant(pair, other), Bool.not(higher(pair, other)))))

def without(pairs: List<&2, CandidatePair>, +pair: CandidatePair, +reversed: List<&2, CandidatePair>) -> List<&2, CandidatePair>:
  match pairs:
    case Nil{}: List.reverse(&2, CandidatePair, reversed)
    case Con{+other, tail}:
      without(tail, pair, Bool.pick(List<&2, CandidatePair>, redundant(pair, other), reversed, Con{other, reversed}))

def inserted(before: Bool, pair: CandidatePair, head: CandidatePair, tail: List<&2, CandidatePair>, reversed: List<&2, CandidatePair>,
             again: List<&2, CandidatePair> -> List<&2, CandidatePair> -> List<&2, CandidatePair>) -> List<&2, CandidatePair>:
  match before:
    case True{}: List.reverse.go(&2, CandidatePair, reversed, Con{pair, Con{head, tail}})
    case False{}: again(tail, Con{head, reversed})

def insert(fuel: Nat, pairs: List<&2, CandidatePair>, +pair: CandidatePair, reversed: List<&2, CandidatePair>) -> List<&2, CandidatePair>:
  match fuel pairs:
    case 0n _: List.reverse.go(&2, CandidatePair, reversed, Con{pair, pairs})
    case 1n+_ Nil{}: List.reverse(&2, CandidatePair, Con{pair, reversed})
    case 1n+p Con{+head, tail}:
      inserted(higher(pair, head), pair, head, tail, reversed,
        rest => rev => insert(p, rest, pair, rev))

def trim(budget: Nat, pairs: List<&2, CandidatePair>, reversed: List<&2, CandidatePair>) -> List<&2, CandidatePair>:
  match budget pairs:
    case 0n _: List.reverse(&2, CandidatePair, reversed)
    case 1n+_ Nil{}: List.reverse(&2, CandidatePair, reversed)
    case 1n+p Con{head, tail}: trim(p, tail, Con{head, reversed})

def retain_checked(skip: Bool, +pairs: List<&2, CandidatePair>, +pair: CandidatePair, cap: Nat) -> List<&2, CandidatePair>:
  match skip:
    case True{}: pairs
    case False{}: trim(cap, insert(Nat.add(length_pairs(pairs, 0n), 1n), without(pairs, pair, []), pair, []), [])

# Retaining top unique pairs while generating bounds sorting storage by cap;
# deduplication precedes truncation, so duplicate high ranks cannot hide a lower
# unique pair that should survive the configured limit.
def retain(+pairs: List<&2, CandidatePair>, +pair: CandidatePair, cap: Nat) -> List<&2, CandidatePair>:
  retain_checked(dominates(pairs, pair, False{}), pairs, pair, cap)

def paired(rank: Maybe<&2, C.Priority>, local: C.Local, remote: C.Candidate,
           pairs: List<&2, CandidatePair>, cap: Nat) -> List<&2, CandidatePair>:
  match rank:
    case None{}: pairs
    case Some{priority}: retain(pairs, CandidatePair{local, remote, priority, Frozen{}}, cap)

def pair_checked(same: Bool, +local: C.Local, +remote: C.Candidate, controlling: Bool,
                 pairs: List<&2, CandidatePair>, cap: Nat) -> List<&2, CandidatePair>:
  match same local remote:
    case False{} _ _: pairs
    case True{} C.Local{C.Candidate{+component, +priority, +foundation, +kind, +address}, +base}
                C.Candidate{+remote_component, +remote_priority, +remote_foundation, +remote_kind, +remote_address}:
      paired(Bool.pick(Maybe<&2, C.Priority>, controlling, C.pair_priority(priority, remote_priority), C.pair_priority(remote_priority, priority)),
        C.Local{C.Candidate{component, priority, foundation, kind, address}, base},
        C.Candidate{remote_component, remote_priority, remote_foundation, remote_kind, remote_address}, pairs, cap)

def same_component(local: C.Local, remote: C.Candidate) -> Bool:
  match local remote:
    case C.Local{C.Candidate{a, _, _, _, _}, _} C.Candidate{b, _, _, _, _}: U32.is_eq(a, b)

def remote_pairs(remotes: List<&2, C.Candidate>, +local: C.Local, +controlling: Bool,
                 pairs: List<&2, CandidatePair>, +cap: Nat) -> List<&2, CandidatePair>:
  match remotes:
    case Nil{}: pairs
    case Con{+remote, tail}:
      remote_pairs(tail, local, controlling, pair_checked(same_component(local, remote), local, remote, controlling, pairs, cap), cap)

def local_pairs(locals: List<&2, C.Local>, +remotes: List<&2, C.Candidate>, +controlling: Bool,
                pairs: List<&2, CandidatePair>, +cap: Nat) -> List<&2, CandidatePair>:
  match locals:
    case Nil{}: pairs
    case Con{local, tail}:
      local_pairs(tail, remotes, controlling, remote_pairs(remotes, local, controlling, pairs, cap), cap)

def priority_used(remotes: List<&2, C.Candidate>, +priority: U32, found: Bool) -> Bool:
  match remotes:
    case Nil{}: found
    case Con{C.Candidate{_, p, _, _, _}, tail}: priority_used(tail, priority, Bool.or(found, U32.is_eq(p, priority)))

def remotes_valid(remotes: List<&2, C.Candidate>, +n: Nat, ok: Bool) -> Bool:
  match remotes:
    case Nil{}: Bool.and(ok, Nat.is_le(n, 64n))
    case Con{C.Candidate{+c, +p, +f, +k, +a}, +tail}:
      remotes_valid(tail, Nat.add(n, 1n), Bool.and(ok, Bool.and(C.valid(C.Candidate{c, p, f, k, a}), Bool.not(priority_used(tail, p, False{})))))

def local_priority_used(locals: List<&2, C.Local>, +priority: U32, found: Bool) -> Bool:
  match locals:
    case Nil{}: found
    case Con{C.Local{C.Candidate{_, p, _, _, _}, _}, tail}: local_priority_used(tail, priority, Bool.or(found, U32.is_eq(p, priority)))

def locals_valid(locals: List<&2, C.Local>, +n: Nat, ok: Bool) -> Bool:
  match locals:
    case Nil{}: Bool.and(ok, Nat.is_le(n, 64n))
    case Con{C.Local{C.Candidate{+c, +p, +f, +k, +a}, +base}, +tail}:
      locals_valid(tail, Nat.add(n, 1n), Bool.and(ok, Bool.and(C.local_valid(C.Local{C.Candidate{c, p, f, k, a}, base}),
        Bool.not(local_priority_used(tail, p, False{})))))

def id_used(streams: List<&2, Stream>, +id: U32, found: Bool) -> Bool:
  match streams:
    case Nil{}: found
    case Con{Stream{i, _, _}, tail}: id_used(tail, id, Bool.or(found, U32.is_eq(i, id)))

def streams_valid(streams: List<&2, Stream>, +n: Nat, ok: Bool) -> Bool:
  match streams:
    case Nil{}: Bool.and(ok, Bool.and(Nat.is_le(1n, n), Nat.is_le(n, 16n)))
    case Con{Stream{+id, locals, remotes}, +tail}:
      streams_valid(tail, Nat.add(n, 1n), Bool.and(ok, Bool.and(Bool.not(id_used(tail, id, False{})),
        Bool.and(locals_valid(locals, 0n, True{}), remotes_valid(remotes, 0n, True{})))))

def local_redundant(first: C.Local, second: C.Local) -> Bool:
  match first second:
    case C.Local{C.Candidate{a, _, _, _, _}, C.Candidate{_, _, _, _, aa}}
         C.Local{C.Candidate{b, _, _, _, _}, C.Candidate{_, _, _, _, ab}}:
      Bool.and(U32.is_eq(a, b), C.address_same(aa, ab))

def local_priority(local: C.Local) -> U32:
  match local:
    case C.Local{C.Candidate{_, p, _, _, _}, _}: p

def local_dominates(locals: List<&2, C.Local>, +local: C.Local, found: Bool) -> Bool:
  match locals:
    case Nil{}: found
    case Con{+other, tail}:
      local_dominates(tail, local, Bool.or(found, Bool.and(local_redundant(local, other), U32.is_le(local_priority(local), local_priority(other)))))

def local_without(locals: List<&2, C.Local>, +local: C.Local, +reversed: List<&2, C.Local>) -> List<&2, C.Local>:
  match locals:
    case Nil{}: List.reverse(&2, C.Local, reversed)
    case Con{+other, tail}:
      local_without(tail, local, Bool.pick(List<&2, C.Local>, local_redundant(local, other), reversed, Con{other, reversed}))

def local_retain(skip: Bool, +locals: List<&2, C.Local>, +local: C.Local) -> List<&2, C.Local>:
  match skip:
    case True{}: locals
    case False{}: List.reverse.go(&2, C.Local, List.reverse(&2, C.Local, local_without(locals, local, [])), [local])

# For a fixed remote priority, pair rank strictly increases with local priority.
# Thus deduplicating a local base/component by the highest advertised priority
# is equivalent to full pair sorting followed by redundancy pruning.
def unique_locals(locals: List<&2, C.Local>, +used: List<&2, C.Local>) -> List<&2, C.Local>:
  match locals:
    case Nil{}: used
    case Con{+local, tail}:
      unique_locals(tail, local_retain(local_dominates(used, local, False{}), used, local))

def remote_count(remotes: List<&2, C.Candidate>, +local: C.Local, +n: Nat) -> Nat:
  match remotes:
    case Nil{}: n
    case Con{remote, tail}:
      remote_count(tail, local, Nat.add(n, Bool.pick(Nat, same_component(local, remote), 1n, 0n)))

def pair_count(locals: List<&2, C.Local>, +remotes: List<&2, C.Candidate>, +n: Nat) -> Nat:
  match locals:
    case Nil{}: n
    case Con{local, tail}: pair_count(tail, remotes, remote_count(remotes, local, n))

def generated(id: U32, +locals: List<&2, C.Local>, +remotes: List<&2, C.Candidate>, controlling: Bool, cap: Nat) -> Quota:
  Quota{id, local_pairs(locals, remotes, controlling, [], cap), pair_count(locals, remotes, 0n)}

def generate(streams: List<&2, Stream>, +controlling: Bool, +cap: Nat, reversed: List<&2, Quota>) -> List<&2, Quota>:
  match streams:
    case Nil{}: List.reverse(&2, Quota, reversed)
    case Con{Stream{id, locals, remotes}, tail}:
      generate(tail, controlling, cap, Con{generated(id, unique_locals(locals, []), remotes, controlling, cap), reversed})

def quota_total(quotas: List<&2, Quota>, +n: Nat) -> Nat:
  match quotas:
    case Nil{}: n
    case Con{Quota{_, _, count}, tail}: quota_total(tail, Nat.add(n, count))

def reduce_pass(quotas: List<&2, Quota>, excess: Nat, reversed: List<&2, Quota>) -> List<&2, Quota> & Nat:
  match quotas excess:
    case _ 0n: (List.reverse.go(&2, Quota, reversed, quotas), 0n)
    case Nil{} n: (List.reverse(&2, Quota, reversed), n)
    case Con{Quota{id, pairs, 0n}, tail} n: reduce_pass(tail, n, Con{Quota{id, pairs, 0n}, reversed})
    case Con{Quota{id, pairs, 1n+n}, tail} 1n+p: reduce_pass(tail, p, Con{Quota{id, pairs, n}, reversed})

def reduce_done(result: List<&2, Quota> & Nat, again: List<&2, Quota> -> Nat -> List<&2, Quota>) -> List<&2, Quota>:
  (quotas, excess) = result
  match excess:
    case 0n: quotas
    case 1n+p: again(quotas, Nat.add(p, 1n))

def reduce(fuel: Nat, quotas: List<&2, Quota>, excess: Nat) -> List<&2, Quota>:
  match fuel:
    case 0n: quotas
    case 1n+p: reduce_done(reduce_pass(quotas, excess, []), lists => left => reduce(p, lists, left))

def allocated(quotas: List<&2, Quota>, reversed: List<&2, Checklist>) -> List<&2, Checklist>:
  match quotas:
    case Nil{}: List.reverse(&2, Checklist, reversed)
    case Con{Quota{id, pairs, count}, tail}:
      allocated(tail, Con{Checklist{id, trim(count, pairs, [])}, reversed})

def seen_foundation(seen: List<&2, CandidatePair>, +pair: CandidatePair, found: Bool) -> Bool:
  match seen:
    case Nil{}: found
    case Con{other, tail}: seen_foundation(tail, pair, Bool.or(found, foundation_same(pair, other)))

def lower_component(pairs: List<&2, CandidatePair>, +pair: CandidatePair, found: Bool) -> Bool:
  match pairs:
    case Nil{}: found
    case Con{+other, tail}:
      lower_component(tail, pair, Bool.or(found, Bool.and(foundation_same(pair, other), U32.is_lt(component(other), component(pair)))))

def initial_pick(waiting: Bool, +pair: CandidatePair, seen: List<&2, CandidatePair>, reversed: List<&2, CandidatePair>,
                 again: List<&2, CandidatePair> -> List<&2, CandidatePair> -> List<&2, CandidatePair> & List<&2, CandidatePair>) -> List<&2, CandidatePair> & List<&2, CandidatePair>:
  match waiting:
    case False{}: again(seen, Con{pair, reversed})
    case True{}: again(Con{pair, seen}, Con{restate(pair, Waiting{}), reversed})

def initial_pairs(fuel: Nat, pairs: List<&2, CandidatePair>, +whole: List<&2, CandidatePair>, +seen: List<&2, CandidatePair>, reversed: List<&2, CandidatePair>) -> List<&2, CandidatePair> & List<&2, CandidatePair>:
  match fuel pairs:
    case 0n _: (List.reverse.go(&2, CandidatePair, reversed, pairs), seen)
    case 1n+_ Nil{}: (List.reverse(&2, CandidatePair, reversed), seen)
    case 1n+p Con{+pair, tail}:
      initial_pick(Bool.and(Bool.not(seen_foundation(seen, pair, False{})), Bool.not(lower_component(whole, pair, False{}))),
        pair, seen, reversed, used => rev => initial_pairs(p, tail, whole, used, rev))

def initial_done(result: List<&2, CandidatePair> & List<&2, CandidatePair>, id: U32, reversed: List<&2, Checklist>,
                 again: List<&2, CandidatePair> -> List<&2, Checklist> -> List<&2, Checklist>) -> List<&2, Checklist>:
  (pairs, seen) = result
  again(seen, Con{Checklist{id, pairs}, reversed})

def initial(fuel: Nat, checklists: List<&2, Checklist>, seen: List<&2, CandidatePair>, reversed: List<&2, Checklist>) -> List<&2, Checklist>:
  match fuel checklists:
    case 0n _: List.reverse.go(&2, Checklist, reversed, checklists)
    case 1n+_ Nil{}: List.reverse(&2, Checklist, reversed)
    case 1n+p Con{Checklist{id, +pairs}, tail}:
      initial_done(initial_pairs(Nat.add(length_pairs(pairs, 0n), 1n), pairs, pairs, seen, []), id, reversed,
        used => rev => initial(p, tail, used, rev))

def limited(+quotas: List<&2, Quota>, cap: Nat) -> List<&2, Checklist>:
  initial(17n, allocated(reduce(Nat.add(quota_total(quotas, 0n), 1n), quotas, Nat.sub(quota_total(quotas, 0n), cap)), []), [], [])

def built(ok: Bool, streams: List<&2, Stream>, controlling: Bool, +limit: U32) -> Maybe<&2, List<&2, Checklist>>:
  match ok:
    case False{}: None{}
    case True{}: Some{limited(generate(streams, controlling, U32.to_nat(limit), []), U32.to_nat(limit))}

# Input order is the usage's checklist order. Default pair limit is 100; accept
# a configured 1..256 limit across the ENTIRE set. Lower ranks are discarded
# round-robin across streams before initial unfreezing.
def build(+streams: List<&2, Stream>, controlling: Bool, +limit: U32) -> Maybe<&2, List<&2, Checklist>>:
  built(Bool.and(streams_valid(streams, 0n, True{}), Bool.and(U32.is_le(1, limit), U32.is_le(limit, 256))), streams, controlling, limit)

def state_code(state: PairState) -> U32:
  match state:
    case Frozen{}: 0
    case Waiting{}: 1
    case InProgress{}: 2
    case Succeeded{}: 3
    case Failed{}: 4

def get_pair(pairs: List<&2, CandidatePair>, index: Nat) -> Maybe<&2, CandidatePair>:
  match pairs index:
    case Nil{} _: None{}
    case Con{head, _} 0n: Some{head}
    case Con{_, tail} 1n+p: get_pair(tail, p)

def get_stream(checklists: List<&2, Checklist>, +id: U32, +index: Nat) -> Maybe<&2, CandidatePair>:
  match checklists:
    case Nil{}: None{}
    case Con{Checklist{+got, pairs}, tail}:
      Bool.pick(Maybe<&2, CandidatePair>, U32.is_eq(id, got), get_pair(pairs, index), get_stream(tail, id, index))

def replace_pair(pairs: List<&2, CandidatePair>, index: Nat, +state: PairState, reversed: List<&2, CandidatePair>) -> List<&2, CandidatePair>:
  match pairs index:
    case Nil{} _: List.reverse(&2, CandidatePair, reversed)
    case Con{head, tail} 0n: List.reverse.go(&2, CandidatePair, reversed, Con{restate(head, state), tail})
    case Con{head, tail} 1n+p: replace_pair(tail, p, state, Con{head, reversed})

def replace_stream(checklists: List<&2, Checklist>, +id: U32, +index: Nat, +state: PairState, reversed: List<&2, Checklist>) -> List<&2, Checklist>:
  match checklists:
    case Nil{}: List.reverse(&2, Checklist, reversed)
    case Con{Checklist{+got, +pairs}, tail}:
      replace_stream(tail, id, index, state, Con{Checklist{got,
        Bool.pick(List<&2, CandidatePair>, U32.is_eq(id, got), replace_pair(pairs, index, state, []), pairs)}, reversed})

def thaw_success(pairs: List<&2, CandidatePair>, +target: CandidatePair, reversed: List<&2, CandidatePair>) -> List<&2, CandidatePair>:
  match pairs:
    case Nil{}: List.reverse(&2, CandidatePair, reversed)
    case Con{CandidatePair{+local, +remote, +rank, +state}, tail}:
      thaw_success(tail, target, Con{CandidatePair{local, remote, rank,
        Bool.pick(PairState, Bool.and(U32.is_eq(state_code(state), 0), foundation_same(CandidatePair{local, remote, rank, state}, target)), Waiting{}, state)}, reversed})

def thaw_all(checklists: List<&2, Checklist>, +target: CandidatePair, reversed: List<&2, Checklist>) -> List<&2, Checklist>:
  match checklists:
    case Nil{}: List.reverse(&2, Checklist, reversed)
    case Con{Checklist{id, pairs}, tail}:
      thaw_all(tail, target, Con{Checklist{id, thaw_success(pairs, target, [])}, reversed})

def transition_checked(ok: Bool, +checklists: List<&2, Checklist>, +id: U32, +index: Nat,
                       target: CandidatePair, +state: PairState, success: Bool) -> Maybe<&2, List<&2, Checklist>>:
  match ok:
    case False{}: None{}
    case True{}:
      Some{Bool.pick(List<&2, Checklist>, success,
        thaw_all(replace_stream(checklists, id, index, state, []), target, []), replace_stream(checklists, id, index, state, []))}

def transition_target(target: Maybe<&2, CandidatePair>, checklists: List<&2, Checklist>, id: U32, index: Nat,
                      from: U32, state: PairState, success: Bool) -> Maybe<&2, List<&2, Checklist>>:
  match target:
    case None{}: None{}
    case Some{CandidatePair{+local, +remote, +rank, old}}:
      transition_checked(U32.is_eq(state_code(old), from), checklists, id, index, CandidatePair{local, remote, rank, Frozen{}}, state, success)

def begin(+checklists: List<&2, Checklist>, +id: U32, +index: Nat) -> Maybe<&2, List<&2, Checklist>>:
  transition_target(get_stream(checklists, id, index), checklists, id, index, 1, InProgress{}, False{})

# This records the check result and unfreezes its foundation on success. It does
# not assert that a mapped address is valid/nominated or conclude the checklist.
def finish_check(+checklists: List<&2, Checklist>, +id: U32, +index: Nat, +success: Bool) -> Maybe<&2, List<&2, Checklist>>:
  transition_target(get_stream(checklists, id, index), checklists, id, index, 2,
    Bool.pick(PairState, success, Succeeded{}, Failed{}), success)
