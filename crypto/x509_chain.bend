import Base
import ./bytes.bend as B
import ./x509_certificate.bend as C
import ./x509_signature.bend as S
import ./x509_public_key.bend as K
import ./x509_name_match.bend as N
import ./unicode32_prepare.bend as U
import ./x509_validity.bend as V
import ./x509_extensions.bend as E
import ./x509_extension_policy.bend as P
import ./x509_eku.bend as EK
import ./x509_hostname.bend as H
import ./x509_identity.bend as I
import ./x509_san.bend as SAN
import ./x509_ca_path.bend as CA

type Identity is Data:
  Dns{bytes: List<&2, U32>}
  Ip{bytes: List<&2, U32>}

type Purpose is Data:
  ServerAuth{}

type Verification is Data:
  Success{}
  Untrusted{}
  WrongIssuer{}
  BadSignature{}
  Expired{}
  NotYetValid{}
  CaBasicConstraints{}
  PathLength{}
  KeyUsage{}
  Eku{}
  UnsupportedCriticalExtension{}
  UnsupportedNameConstraints{}
  UnsupportedName{}
  IdentityMismatch{}
  DepthLimit{}
  Cycle{}
  Duplicate{}
  SearchLimit{}
  InputLimit{}
  Malformed{}

# Only public admitted field bytes are copiable. Affine certificate/key/Name
# records and Unicode tables are never implicitly duplicated.
type Node is Data:
  Node{raw: List<&2, U32>, version: U32, issuer: List<&2, U32>, subject: List<&2, U32>,
    spki: List<&2, U32>, validity: List<&2, U32>, extensions: Maybe<&2, List<&2, U32>>}

type Candidate is Data:
  Candidate{node: Node, trusted: Bool}

type Search is Type:
  Search{tables: U.Tables, budget: U32, result: Verification}

def same(a: List<&2, U32>, b: List<&2, U32>) -> Bool:
  I.same(a, b, False{}, True{})

def seen.checked(equal: Bool, next: Unit -> Bool) -> Bool:
  match equal:
    case True{}: True{}
    case False{}: next(Unit{})

def seen(+bytes: List<&2, U32>, nodes: List<&2, Node>) -> Bool:
  match nodes:
    case Nil{}: False{}
    case Con{Node{raw, _, _, _, _, _, _}, rest}:
      seen.checked(same(bytes, raw), u => seen(bytes, rest))

def node.decoded(raw: List<&2, U32>, value: Maybe<&1, C.Certificate>) -> Maybe<Node>:
  match value:
    case Some{C.Certificate{C.Tbs{C.Header{_, version, _, _},
      C.Identity{issuer, validity, subject, spki}, C.Tail{_, _, extensions}}, _, _}}:
      Some{Node{raw, version, issuer, subject, spki, validity, extensions}}
    case None{}: None{}

def node(+raw: List<&2, U32>) -> Maybe<Node>:
  node.decoded(raw, C.decode(raw))

type Nodes is Data:
  Nodes{items: List<&2, Node>}
  NodesFailed{reason: Verification}

def nodes.unique(duplicate: Bool, item: Node, reversed: List<&2, Node>,
  next: List<&2, Node> -> Nodes) -> Nodes:
  match duplicate:
    case True{}: NodesFailed{Duplicate{}}
    case False{}: next(Con{item, reversed})

def nodes.got(+reversed: List<&2, Node>, value: Maybe<Node>,
  next: List<&2, Node> -> Nodes) -> Nodes:
  match value:
    case None{}: NodesFailed{Malformed{}}
    case Some{+item}:
      match item:
        case Node{raw, _, _, _, _, _, _}: nodes.unique(seen(raw, reversed), item, reversed, next)

def nodes(input: List<&2, List<&2, U32>>, reversed: List<&2, Node>, left: Nat) -> Nodes:
  match input left:
    case Nil{} _: Nodes{List.reverse(&2, Node, reversed)}
    case Con{raw, rest} 1n+p: nodes.got(reversed, node(raw), xs => nodes(rest, xs, p))
    case _ 0n: NodesFailed{InputLimit{}}

def time.before(early: Bool, after: Nat, now: Nat) -> Verification:
  match early:
    case True{}: NotYetValid{}
    case False{}: Bool.pick(Verification, Nat.is_gt(now, after), Expired{}, Success{})

def time(value: Maybe<&1, V.Validity>, +now: Nat) -> Verification:
  match value:
    case None{}: Malformed{}
    case Some{V.Validity{before, after}}: time.before(Nat.is_lt(now, before), after, now)

def critical.known(unsupported: Bool, next: Unit -> Verification) -> Verification:
  match unsupported:
    case True{}: UnsupportedCriticalExtension{}
    case False{}: next(Unit{})

def critical.san(value: Maybe<&1, Bool>, next: Unit -> Verification) -> Verification:
  match value:
    case None{}: Malformed{}
    case Some{False{}}: UnsupportedCriticalExtension{}
    case Some{True{}}: next(Unit{})

def critical(entries: List<&1, E.Extension>) -> Verification:
  match entries:
    case Nil{}: Success{}
    # A recognized authorization constraint cannot be silently ignored even
    # when a nonconforming issuer marks it noncritical. Reject both forms.
    case Con{E.Extension{[85,29,30], _, _}, _}: UnsupportedNameConstraints{}
    case Con{E.Extension{[85,29,17], True{}, bytes}, rest}:
      critical.san(SAN.inspect(bytes), u => critical(rest))
    case Con{E.Extension{oid, +is_critical, _}, rest}:
      critical.known(Bool.and(is_critical, U32.is_eq(P.kind(oid), 0)), u => critical(rest))

def critical.optional(entries: Maybe<&1, List<&1, E.Extension>>) -> Verification:
  match entries:
    case None{}: Malformed{}
    case Some{entries}: critical(entries)

def key(value: Maybe<&1, K.PublicKey>) -> Verification:
  match value:
    case None{}: Malformed{}
    case Some{_}: Success{}

def extension_policy(value: Maybe<&1, P.Admission>) -> Verification:
  match value:
    case None{}: Malformed{}
    case Some{_}: Success{}

def checked(status: Verification, next: Unit -> Verification) -> Verification:
  match status:
    case Success{}: next(Unit{})
    case reason: reason

def admitted(value: Node, +now: Nat) -> Verification:
  match value:
    case Node{raw, _, _, _, spki, validity, extensions}:
      checked(time(V.decode(validity), now), u =>
        checked(key(K.decode(spki)), u =>
          checked(critical.optional(E.optional(extensions)), u => extension_policy(P.certificate(raw)))))

def names(value: Node, tables: U.Tables) -> U.Tables & Maybe<&1, Bool>:
  match value:
    case Node{_, _, issuer, subject, _, _, _}: N.compare(tables, issuer, subject)

def usage(optional: Maybe<&2, List<&2, U32>>) -> Verification:
  Bool.pick(Verification, EK.signing(optional), Success{}, KeyUsage{})

def eku(optional: Maybe<&2, List<&2, U32>>) -> Verification:
  Bool.pick(Verification, EK.permits(optional, [43,6,1,5,5,7,3,1], False{}), Success{}, Eku{})

def leaf.policy(value: Maybe<&1, P.Admission>) -> Verification:
  match value:
    case Some{P.Admission{_, _, key_usage, _, deferred}}:
      checked(usage(key_usage), u => eku(P.eku.find(deferred)))
    case None{}: Malformed{}

def identity(raw: List<&2, U32>, expected: Identity) -> Verification:
  match expected:
    case Dns{bytes}: Bool.pick(Verification, H.certificate(raw, 0, bytes), Success{}, IdentityMismatch{})
    case Ip{bytes}: Bool.pick(Verification, H.certificate(raw, 1, bytes), Success{}, IdentityMismatch{})

def ca.result(value: CA.Decision) -> Verification:
  match value:
    case CA.Allowed{}: Success{}
    case CA.InvalidCa{}: CaBasicConstraints{}
    case CA.InvalidUsage{}: KeyUsage{}
    case CA.Exceeded{}: PathLength{}

def ca.policy(version: U32, below: U32, value: Maybe<&1, P.Admission>) -> Verification:
  match value:
    case Some{P.Admission{basic, _, key_usage, _, deferred}}:
      checked(ca.result(CA.check(version, basic, key_usage, below)), u => eku(P.eku.find(deferred)))
    case None{}: Malformed{}

def candidates(nodes: List<&2, Node>, +trusted: Bool, tail: List<&2, Candidate>) -> List<&2, Candidate>:
  match nodes:
    case Nil{}: tail
    case Con{item, rest}: Con{Candidate{item, trusted}, candidates(rest, trusted, tail)}

def linked(child: Node, parent: Node, tables: U.Tables) -> U.Tables & Maybe<&1, Bool>:
  match child parent:
    case Node{_, _, issuer, _, _, _, _} Node{_, _, _, subject, _, _, _}:
      N.compare(tables, issuer, subject)

def signature(child: Node, parent: Node) -> Bool:
  match child parent:
    case Node{raw, _, _, _, _, _, _} Node{_, _, _, _, spki, _, _}:
      S.verify_signature(spki, raw)

# Every candidate examination spends global fuel, including failed name
# matches and backtracking. The budget is threaded back from failed branches.
def branch.checked(status: Verification, tables: U.Tables, budget: U32,
  next: U.Tables -> Search) -> Search:
  match status:
    case Success{}: next(tables)
    case reason: Search{tables, budget, reason}

def branch.when(valid: Bool, tables: U.Tables, budget: U32, reason: Verification,
  next: U.Tables -> Search) -> Search:
  match valid:
    case False{}: Search{tables, budget, reason}
    case True{}: next(tables)

# A continuation keeps the recursive search in one definition. Branch helpers
# own only their affine Unicode state and return consumed global fuel.
def Descend() -> Type:
  U.Tables -> Node -> List<&2, Node> -> U32 -> U32 -> U32 -> Verification -> Search

def branch.trusted(trusted: Bool, tables: U.Tables, +parent: Node, visited: List<&2, Node>,
  depth: U32, below: U32, budget: U32, +self_issued: Bool, next: Descend()) -> Search:
  match trusted:
    case True{}: Search{tables, budget, Success{}}
    case False{}:
      next(tables, parent, Con{parent, visited}, U32.inc(depth),
        CA.advance(self_issued, below), budget,
        Bool.pick(Verification, self_issued, Untrusted{}, WrongIssuer{}))

def branch.ready(+parent: Node, trusted: Bool, visited: List<&2, Node>,
  depth: U32, +below: U32, +budget: U32, tables: U.Tables, self_issued: Bool, next: Descend()) -> Search:
  match parent:
    case Node{raw, version, _, _, _, _, _}:
      branch.checked(ca.policy(version, below, P.certificate(raw)), tables, budget, t =>
        branch.trusted(trusted, t, parent, visited, depth, below, budget, self_issued, next))

def branch.names(parent: Node, trusted: Bool, visited: List<&2, Node>,
  depth: U32, below: U32, budget: U32, result: U.Tables & Maybe<&1, Bool>, next: Descend()) -> Search:
  (tables, self_issued) = result
  match self_issued:
    case None{}: Search{tables, budget, UnsupportedName{}}
    case Some{self_issued}: branch.ready(parent, trusted, visited, depth, below, budget, tables, self_issued, next)

def repeated(child: Node, raw: List<&2, U32>) -> Verification:
  match child:
    case Node{bytes, _, _, _, _, _, _}: Bool.pick(Verification, same(bytes, raw), Untrusted{}, Cycle{})

def branch(tables: U.Tables, +child: Node, +parent: Node, trusted: Bool,
  +visited: List<&2, Node>, +depth: U32, below: U32, +now: Nat, +budget: U32, next: Descend()) -> Search:
  match parent:
    case Node{+raw, _, _, _, _, _, _}:
      branch.when(Bool.not(seen(raw, visited)), tables, budget, repeated(child, raw), t =>
        branch.when(U32.is_lt(depth, 8), t, budget, DepthLimit{}, t =>
          branch.when(signature(child, parent), t, budget, BadSignature{}, t =>
            branch.checked(admitted(parent, now), t, budget, t =>
              branch.names(parent, trusted, visited, depth, below, budget, names(parent, t), next)))))

def search.tried(tried: Search, next: U.Tables -> U32 -> Verification -> Search) -> Search:
  match tried:
    case Search{tables, budget, Success{}}: Search{tables, budget, Success{}}
    case Search{tables, budget, SearchLimit{}}: Search{tables, budget, SearchLimit{}}
    case Search{tables, budget, reason}: next(tables, budget, reason)

def failure(previous: Verification, reason: Verification) -> Verification:
  match previous:
    case WrongIssuer{}: reason
    case Untrusted{}: reason
    case previous: previous

def search.linked(result: U.Tables & Maybe<&1, Bool>, budget: U32,
  matched: U.Tables -> Search, missed: U.Tables -> Search, unsupported: U.Tables -> Search) -> Search:
  (tables, equal) = result
  match equal:
    case None{}: unsupported(tables)
    case Some{False{}}: missed(tables)
    case Some{True{}}: matched(tables)

def search.fuel(budget: U32, tables: U.Tables, next: U.Tables -> U32 -> Search) -> Search:
  match budget:
    case 0: Search{tables, 0, SearchLimit{}}
    case budget: next(tables, U32.sub(budget, 1))

def search(fuel: Nat, tables: U.Tables, +child: Node, candidates: List<&2, Candidate>, +pool: List<&2, Candidate>,
  +visited: List<&2, Node>, +depth: U32, +below: U32, +now: Nat, budget: U32, +previous: Verification) -> Search:
  match fuel candidates:
    case 0n _: Search{tables, budget, SearchLimit{}}
    case 1n+_ Nil{}: Search{tables, budget, previous}
    case 1n+ +fuel_left Con{Candidate{+parent, trusted}, +remaining}:
      search.fuel(budget, tables, t => +b =>
        search.linked(linked(child, parent, t), b,
          t => search.tried(branch(t, child, parent, trusted, visited, depth, below, now, b,
            t => p => v => d => c => b => r => search(fuel_left, t, p, pool, pool, v, d, c, now, b, r)),
            t => b => r => search(fuel_left, t, child, remaining, pool, visited, depth, below, now, b, failure(previous, r))),
          t => search(fuel_left, t, child, remaining, pool, visited, depth, below, now, b, previous),
          t => search(fuel_left, t, child, remaining, pool, visited, depth, below, now, b, failure(previous, UnsupportedName{}))))

def finish(value: Search) -> U.Tables & Verification:
  match value:
    case Search{tables, _, result}: (tables, result)

def start.anchors(anchors: List<&2, Node>, tables: U.Tables, +leaf: Node,
  peers: List<&2, Node>, now: Nat, self_issued: Bool) -> U.Tables & Verification:
  match anchors:
    case Nil{}: (tables, Untrusted{})
    case anchors:
      +pool = candidates(anchors, True{}, candidates(peers, False{}, []))
      finish(search(512n, tables, leaf, pool, pool, [leaf], 1, 0, now, 512,
        Bool.pick(Verification, self_issued, Untrusted{}, WrongIssuer{})))

def start.names(+leaf: Node, peers: List<&2, Node>, anchors: List<&2, Node>, now: Nat,
  result: U.Tables & Maybe<&1, Bool>) -> U.Tables & Verification:
  (tables, self_issued) = result
  match self_issued:
    case None{}: (tables, UnsupportedName{})
    case Some{self_issued}: start.anchors(anchors, tables, leaf, peers, now, self_issued)

def start.checked(status: Verification, tables: U.Tables,
  next: U.Tables -> U.Tables & Verification) -> U.Tables & Verification:
  match status:
    case Success{}: next(tables)
    case reason: (tables, reason)

def start(tables: U.Tables, +leaf: Node, peers: List<&2, Node>, anchors: List<&2, Node>,
  expected: Identity, +now: Nat) -> U.Tables & Verification:
  match leaf:
    case Node{+raw, _, _, _, _, _, _}:
      start.checked(admitted(leaf, now), tables, t =>
        start.checked(leaf.policy(P.certificate(raw)), t, t =>
          start.checked(identity(raw, expected), t, t =>
            start.names(leaf, peers, anchors, now, names(leaf, t)))))

def decoded(tables: U.Tables, presented: Nodes, anchors: Nodes, identity: Identity, now: Nat) -> U.Tables & Verification:
  match presented anchors:
    case NodesFailed{reason} _: (tables, reason)
    case _ NodesFailed{reason}: (tables, reason)
    case Nodes{Nil{}} _: (tables, Malformed{})
    case Nodes{Con{leaf, peers}} Nodes{anchors}: start(tables, leaf, peers, anchors, identity, now)

def reference(value: Identity) -> Bool:
  match value:
    case Dns{bytes}: I.domain(bytes)
    case Ip{+bytes}: Bool.and(I.ip_length(bytes), B.valid(bytes))

# One authorization boundary, no OS/clock/network/crypto effects. The reusable
# affine Unicode state must come from U.tables (authenticated bundled assets).
# now is civil UTC seconds since 0001-01-01, not IO.now or Unix seconds.
# At most 16 peer certificates + 16 anchors, 8 certificates/path (leaf+anchor
# included), 512 candidate examinations, 65535 bytes/certificate. No fetching.
def verify(tables: U.Tables, presented: List<&2, List<&2, U32>>,
  anchors: List<&2, List<&2, U32>>, +identity: Identity, purpose: Purpose, +now: Nat) -> U.Tables & Verification:
  match purpose:
    case ServerAuth{}:
      start.checked(Bool.pick(Verification, Bool.and(reference(identity), Nat.is_le(now, V.last_second())), Success{}, Malformed{}),
        tables, t => decoded(t, nodes(presented, [], 16n), nodes(anchors, [], 16n), identity, now))

def show(value: Verification) -> String:
  match value:
    case Success{}: "success"
    case Untrusted{}: "untrusted"
    case WrongIssuer{}: "wrong-issuer"
    case BadSignature{}: "bad-signature"
    case Expired{}: "expired"
    case NotYetValid{}: "not-yet-valid"
    case CaBasicConstraints{}: "ca-basic-constraints"
    case PathLength{}: "path-length"
    case KeyUsage{}: "key-usage"
    case Eku{}: "eku"
    case UnsupportedCriticalExtension{}: "unsupported-critical-extension"
    case UnsupportedNameConstraints{}: "unsupported-name-constraints"
    case UnsupportedName{}: "unsupported-name"
    case IdentityMismatch{}: "identity-mismatch"
    case DepthLimit{}: "depth-limit"
    case Cycle{}: "cycle"
    case Duplicate{}: "duplicate"
    case SearchLimit{}: "search-limit"
    case InputLimit{}: "input-limit"
    case Malformed{}: "malformed"
