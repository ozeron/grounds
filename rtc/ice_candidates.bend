import Base
import ./stun.bend as Stun
import ./ice_binding.bend as Ice
import ../utf8/utf8.bend as U

type Flavor is Data:
  Host{}
  ServerReflexive{}
  PeerReflexive{}
  Relay{}

type Candidate is Data:
  Candidate{component: U32, priority: U32, foundation: String, kind: Flavor, address: Stun.IPv4}

# The base is explicit, including its foundation and priority. A reflexive
# candidate's base can be omitted from signaling but is still known locally.
type Local is Data:
  Local{candidate: Candidate, base: Candidate}

type Priority is Data:
  Priority{high: U32, low: U32}

def address_valid(address: Stun.IPv4) -> Bool:
  match address:
    case Stun.IPv4{a, b, c, d, +port}:
      Bool.and(Bool.and(Bool.and(U32.is_le(a, 255), U32.is_le(b, 255)),
        Bool.and(U32.is_le(c, 255), U32.is_le(d, 255))), Bool.and(U32.is_le(1, port), U32.is_le(port, 65535)))

def address_same(first: Stun.IPv4, second: Stun.IPv4) -> Bool:
  match first second:
    case Stun.IPv4{a, b, c, d, p} Stun.IPv4{w, x, y, z, q}:
      Bool.and(Bool.and(Bool.and(U32.is_eq(a, w), U32.is_eq(b, x)),
        Bool.and(U32.is_eq(c, y), U32.is_eq(d, z))), U32.is_eq(p, q))

def kind_code(kind: Flavor) -> U32:
  match kind:
    case Host{}: 0
    case ServerReflexive{}: 1
    case PeerReflexive{}: 2
    case Relay{}: 3

def reflexive(kind: Flavor) -> Bool:
  match kind:
    case ServerReflexive{}: True{}
    case PeerReflexive{}: True{}
    case _: False{}

def valid(candidate: Candidate) -> Bool:
  match candidate:
    case Candidate{+component, +priority, foundation, _, address}:
      Bool.and(Bool.and(Bool.and(U32.is_le(1, component), U32.is_le(component, 256)),
        Bool.and(U32.is_le(1, priority), U32.is_le(priority, 2147483647))),
        Bool.and(Ice.credential(U.encode(foundation), 1n, 32n), address_valid(address)))

def same(a: Candidate, b: Candidate) -> Bool:
  match a b:
    case Candidate{ca, pa, fa, ka, aa} Candidate{cb, pb, fb, kb, ab}:
      Bool.and(Bool.and(U32.is_eq(ca, cb), U32.is_eq(pa, pb)),
        Bool.and(Bool.and(String.eq(fa, fb), U32.is_eq(kind_code(ka), kind_code(kb))), address_same(aa, ab)))

def local_valid(local: Local) -> Bool:
  match local:
    case Local{Candidate{+component, +priority, +foundation, +kind, +address},
               Candidate{+base_component, +base_priority, +base_foundation, +base_kind, +base_address}}:
      Bool.and(Bool.and(valid(Candidate{component, priority, foundation, kind, address}),
        valid(Candidate{base_component, base_priority, base_foundation, base_kind, base_address})),
        Bool.and(Bool.and(U32.is_eq(component, base_component), Bool.not(reflexive(base_kind))),
          Bool.or(reflexive(kind), same(Candidate{component, priority, foundation, kind, address},
            Candidate{base_component, base_priority, base_foundation, base_kind, base_address}))))

def check_candidate(local: Local) -> Candidate:
  match local:
    case Local{Candidate{component, priority, foundation, +kind, address}, base}:
      Bool.pick(Candidate, reflexive(kind), base, Candidate{component, priority, foundation, kind, address})

def candidate_priority_checked(ok: Bool, preference: U32, local: U32, component: U32) -> Maybe<&2, U32>:
  match ok:
    case False{}: None{}
    case True{}:
      Some{(preference * 16777216 + local * 256 + (256 - component) : U32)}

# RFC 8445 5.1.2.1; reject the all-zero result required to be a positive priority.
def candidate_priority(+preference: U32, +local: U32, +component: U32) -> Maybe<&2, U32>:
  candidate_priority_checked(Bool.and(Bool.and(U32.is_le(preference, 126), U32.is_le(local, 65535)),
    Bool.and(Bool.and(U32.is_le(1, component), U32.is_le(component, 256)),
      Bool.or(Bool.or(U32.is_gt(preference, 0), U32.is_gt(local, 0)), U32.is_lt(component, 256)))), preference, local, component)

def pair_checked(ok: Bool, +g: U32, +d: U32) -> Maybe<&2, Priority>:
  match ok:
    case False{}: None{}
    case True{}:
      Some{Priority{U32.min(g, d), (U32.max(g, d) * 2 + Bool.pick(U32, U32.is_gt(g, d), 1, 0) : U32)}}

# 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D). Two words retain every bit without
# exceeding Bend's Nat immediate; valid candidate priorities prevent low overflow.
def pair_priority(+g: U32, +d: U32) -> Maybe<&2, Priority>:
  pair_checked(Bool.and(Bool.and(U32.is_le(1, g), U32.is_le(g, 2147483647)),
    Bool.and(U32.is_le(1, d), U32.is_le(d, 2147483647))), g, d)

def greater(a: Priority, b: Priority) -> Bool:
  match a b:
    case Priority{+ah, al} Priority{+bh, bl}:
      Bool.or(U32.is_gt(ah, bh), Bool.and(U32.is_eq(ah, bh), U32.is_gt(al, bl)))

def host(address: Stun.IPv4) -> String:
  match address:
    case Stun.IPv4{a, b, c, d, _}: U32.show(a) ++ "." ++ U32.show(b) ++ "." ++ U32.show(c) ++ "." ++ U32.show(d)

def port(address: Stun.IPv4) -> U32:
  match address:
    case Stun.IPv4{_, _, _, _, p}: p

def address_checked(valid: Bool, address: Stun.IPv4) -> Maybe<&2, Stun.IPv4>:
  match valid:
    case True{}: Some{address}
    case False{}: None{}

def address_numbers(a: Maybe<&2, U32>, b: Maybe<&2, U32>, c: Maybe<&2, U32>, d: Maybe<&2, U32>,
                    +port: U32, +text: String) -> Maybe<&2, Stun.IPv4>:
  match a b c d:
    case Some{+a} Some{+b} Some{+c} Some{+d}:
      address_checked(Bool.and(address_valid(Stun.IPv4{a, b, c, d, port}), String.eq(host(Stun.IPv4{a, b, c, d, port}), text)), Stun.IPv4{a, b, c, d, port})
    case _ _ _ _: None{}

def address_parts(parts: List<&2, String>, port: U32, text: String) -> Maybe<&2, Stun.IPv4>:
  match parts:
    case [a, b, c, d]: address_numbers(U32.read(a), U32.read(b), U32.read(c), U32.read(d), port, text)
    case _: None{}

# Canonical IPv4 literal from the UDP effect. It never accepts DNS names or
# relies on a source address claimed inside an unauthenticated datagram.
def address_read(+text: String, port: U32) -> Maybe<&2, Stun.IPv4>:
  address_parts(String.split(text, '.'), port, text)
