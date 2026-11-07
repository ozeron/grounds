import Base

# IP address text for the stack, in Bend: strict IPv4 and IPv6 parsing and
# the RFC 5952 canonical IPv6 text. The C and JavaScript effects only take
# and give addresses as text; what counts as one is decided here.
#
# IPv6 is the RFC 4291 section 2.2 text form with hex groups only: one to
# four hex digits per group, eight groups, or fewer around a single "::"
# that stands for at least one group. Not accepted: a zone ID ("%en0" or a
# URL's "%25en0"), the dotted IPv4 tail ("::ffff:192.0.2.1"), and anything
# longer than eight groups. IPv4 is four decimal parts 0..255 without
# leading zeros (as the runtime's address parser).
#
# Every function here takes its input once. The legacy client graph imports
# this module through url.bend and must not make a constructor hot (shared).

# a hex digit's value; 16 for any other char
def hex.val(+c: U32) -> U32:
  Bool.pick(U32, Bool.and(U32.is_ge(c, 48), U32.is_le(c, 57)), U32.sub(c, 48),
    Bool.pick(U32, Bool.and(U32.is_ge(c, 97), U32.is_le(c, 102)), U32.sub(c, 87),
      Bool.pick(U32, Bool.and(U32.is_ge(c, 65), U32.is_le(c, 70)), U32.sub(c, 55), 16)))

# IPv6 parsing
# ------------
# One step per char over a state: m is where the parser is (0 nothing
# read, 1 a leading ":", 2 in a group, 3 after the ":" that ended a group,
# 4 right after "::"); v, nd: the current group's value and digits; h: the
# groups before "::" (or all of them), reversed; t: the groups after it,
# reversed; dbl: whether "::" came; k: the groups so far.

type S6 is Data:
  S6{m: U32, v: U32, nd: U32, h: List<&2, U32>, t: List<&2, U32>, dbl: Bool, k: U32}
  S6Bad{}

def v6.zeros(n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+p:
      v6.zeros(p, Con{0, acc})

# the group v joins the groups before or after "::"
def v6.push(+v: U32, h: List<&2, U32>, t: List<&2, U32>, dbl: Bool, +k: U32) -> S6:
  match dbl:
    case True{}:
      S6{3, 0, 0, h, Con{v, t}, True{}, U32.inc(k)}
    case False{}:
      S6{3, 0, 0, Con{v, h}, t, False{}, U32.inc(k)}

# a group's first digit
def v6.first(ok: Bool, +x: U32, h: List<&2, U32>, t: List<&2, U32>, dbl: Bool, +k: U32) -> S6:
  match ok:
    case True{}:
      S6{2, x, 1, h, t, dbl, k}
    case False{}:
      S6Bad{}

# "::": never twice
def v6.dbl(ok: Bool, h: List<&2, U32>, t: List<&2, U32>, +k: U32) -> S6:
  match ok:
    case True{}:
      S6{4, 0, 0, h, t, True{}, k}
    case False{}:
      S6Bad{}

def v6.more(ok: Bool, +x: U32, +v: U32, +nd: U32, h: List<&2, U32>, t: List<&2, U32>, dbl: Bool, +k: U32) -> S6:
  match ok:
    case True{}:
      S6{2, U32.add(U32.mul(v, 16), x), U32.inc(nd), h, t, dbl, k}
    case False{}:
      S6Bad{}

def v6.end.grp(ok: Bool, +v: U32, h: List<&2, U32>, t: List<&2, U32>, dbl: Bool, +k: U32) -> S6:
  match ok:
    case True{}:
      v6.push(v, h, t, dbl, k)
    case False{}:
      S6Bad{}

# in a group: a fifth digit, or a ninth group, is too many
def v6.in.grp(hex: Bool, +x: U32, +colon: Bool, +v: U32, +nd: U32, h: List<&2, U32>, t: List<&2, U32>, dbl: Bool, +k: U32) -> S6:
  match hex:
    case True{}:
      v6.more(U32.is_lt(nd, 4), x, v, nd, h, t, dbl, k)
    case False{}:
      v6.end.grp(Bool.and(colon, U32.is_lt(k, 8)), v, h, t, dbl, k)

def v6.after.sep(colon: Bool, +hex: Bool, +x: U32, h: List<&2, U32>, t: List<&2, U32>, dbl: Bool, +k: U32) -> S6:
  match colon:
    case True{}:
      v6.dbl(Bool.not(dbl), h, t, k)
    case False{}:
      v6.first(hex, x, h, t, dbl, k)

def v6.at.start(colon: Bool, +hex: Bool, +x: U32) -> S6:
  match colon:
    case True{}:
      S6{1, 0, 0, [], [], False{}, 0}
    case False{}:
      v6.first(hex, x, [], [], False{}, 0)

def v6.at(m0: Bool, m1: Bool, m2: Bool, m3: Bool, +x: U32, +colon: Bool, +v: U32, +nd: U32, h: List<&2, U32>, t: List<&2, U32>, dbl: Bool, +k: U32) -> S6:
  match m0 m1 m2 m3:
    case True{} _ _ _:
      v6.at.start(colon, U32.is_lt(x, 16), x)
    case False{} True{} _ _:
      v6.dbl(colon, h, t, k)
    case False{} False{} True{} _:
      v6.in.grp(U32.is_lt(x, 16), x, colon, v, nd, h, t, dbl, k)
    case False{} False{} False{} True{}:
      v6.after.sep(colon, U32.is_lt(x, 16), x, h, t, dbl, k)
    case False{} False{} False{} False{}:
      v6.first(U32.is_lt(x, 16), x, h, t, dbl, k)

def v6.step(st: S6, +c: U32) -> S6:
  match st:
    case S6{+m, +v, +nd, h, t, dbl, +k}:
      v6.at(U32.is_eq(m, 0), U32.is_eq(m, 1), U32.is_eq(m, 2), U32.is_eq(m, 3), hex.val(c), U32.is_eq(c, 58), v, nd, h, t, dbl, k)
    case S6Bad{}:
      S6Bad{}

def v6.full(ok: Bool, h: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case True{}:
      Some{List.reverse(&2, U32, h)}
    case False{}:
      None{}

def v6.gap(ok: Bool, h: List<&2, U32>, t: List<&2, U32>, +k: U32) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case True{}:
      Some{List.append(&2, U32, List.reverse(&2, U32, h), v6.zeros(U32.to_nat(U32.sub(8, k)), List.reverse(&2, U32, t)))}
    case False{}:
      None{}

# eight groups without "::"; with it, at most seven written ones
def v6.finish(st: S6) -> Maybe<&2, List<&2, U32>>:
  match st:
    case S6{_, _, _, h, t, True{}, +k}:
      v6.gap(U32.is_le(k, 7), h, t, k)
    case S6{_, _, _, h, t, False{}, +k}:
      v6.full(U32.is_eq(k, 8), h)
    case S6Bad{}:
      None{}

def v6.end.m(grp: Bool, gap: Bool, +v: U32, h: List<&2, U32>, t: List<&2, U32>, dbl: Bool, +k: U32) -> Maybe<&2, List<&2, U32>>:
  match grp gap:
    case True{} _:
      v6.finish(v6.end.grp(U32.is_lt(k, 8), v, h, t, dbl, k))
    case False{} True{}:
      v6.finish(S6{4, 0, 0, h, t, dbl, k})
    case False{} False{}:
      None{}

# the end: in a group (closing it), or right after "::"
def v6.end(st: S6) -> Maybe<&2, List<&2, U32>>:
  match st:
    case S6{+m, +v, _, h, t, dbl, +k}:
      v6.end.m(U32.is_eq(m, 2), U32.is_eq(m, 4), v, h, t, dbl, k)
    case S6Bad{}:
      None{}

def v6.go(s: String, st: S6) -> Maybe<&2, List<&2, U32>>:
  match s:
    case SNil{}:
      v6.end(st)
    case SCon{Chr{+c}, r}:
      v6.go(r, v6.step(st, c))

# IPv6 text to its eight 16-bit groups, or None{}
def v6.parse(s: String) -> Maybe<&2, List<&2, U32>>:
  v6.go(s, S6{0, 0, 0, [], [], False{}, 0})

# eight groups to the sixteen bytes of an iPAddress, in network order
def v6.bytes(gs: List<&2, U32>) -> List<&2, U32>:
  match gs:
    case Nil{}:
      Nil{}
    case Con{+g, t}:
      Con{(g >> 8n : U32), Con{(g .&. 255 : U32), v6.bytes(t)}}

# Canonical IPv6 text (RFC 5952 section 4)
# ----------------------------------------
# lowercase hex without leading zeros; the longest run of two or more zero
# groups (the first of equal runs) is "::"; a lone zero group stays "0".

type Run is Data:
  Run{cs: U32, cl: U32, bs: U32, bl: U32}

# the longest zero run so far (bs, bl) and the current one (cs, cl), after
# group g at index i; a longer run replaces the best, an equal one does not
def v6.run.step(r: Run, +g: U32, +i: U32) -> Run:
  match r:
    case Run{+cs, +cl, +bs, +bl}:
      Bool.pick(Run, U32.is_eq(g, 0),
        Run{Bool.pick(U32, U32.is_eq(cl, 0), i, cs), U32.inc(cl), bs, bl},
        Run{0, 0, Bool.pick(U32, U32.is_gt(cl, bl), cs, bs), Bool.pick(U32, U32.is_gt(cl, bl), cl, bl)})

def v6.run(gs: List<&2, U32>, +i: U32, r: Run) -> Run:
  match gs:
    case Nil{}:
      v6.run.step(r, 1, i)
    case Con{+g, t}:
      v6.run(t, U32.inc(i), v6.run.step(r, g, i))

def v6.nib(+d: U32) -> Char:
  Chr{Bool.pick(U32, U32.is_lt(d, 10), U32.add(d, 48), U32.add(d, 87))}

def v6.put(ok: Bool, +d: U32, out: String) -> String:
  match ok:
    case True{}:
      SCon{v6.nib(d), out}
    case False{}:
      out

# a group's hex digits onto the reversed out
def v6.hex(+g: U32, out: String) -> String:
  SCon{v6.nib((g .&. 15 : U32)), v6.put(U32.is_ge(g, 16), ((g >> 4n : U32) .&. 15 : U32), v6.put(U32.is_ge(g, 256), ((g >> 8n : U32) .&. 15 : U32), v6.put(U32.is_ge(g, 4096), ((g >> 12n : U32) .&. 15 : U32), out)))}

def v6.grp.text(lead: Bool, +g: U32, out: String) -> String:
  match lead:
    case True{}:
      v6.hex(g, SCon{':', out})
    case False{}:
      v6.hex(g, out)

def v6.run.text(first: Bool, out: String) -> String:
  match first:
    case True{}:
      SCon{':', SCon{':', out}}
    case False{}:
      out

# group g at index i onto the reversed out: the run's first group is "::",
# its others nothing; a group after another (not after the run) gets ":"
def v6.text.g(inside: Bool, +g: U32, +i: U32, +bs: U32, +bl: U32, out: String) -> String:
  match inside:
    case True{}:
      v6.run.text(U32.is_eq(i, bs), out)
    case False{}:
      v6.grp.text(Bool.and(U32.is_gt(i, 0), U32.is_ne(i, U32.add(bs, bl))), g, out)

def v6.text(gs: List<&2, U32>, +i: U32, +bs: U32, +bl: U32, out: String) -> String:
  match gs:
    case Nil{}:
      String.reverse(out)
    case Con{+g, t}:
      v6.text(t, U32.inc(i), bs, bl, v6.text.g(Bool.and(U32.is_ge(i, bs), U32.is_lt(i, U32.add(bs, bl))), g, i, bs, bl, out))

type G2 is Data:
  G2{a: List<&2, U32>, b: List<&2, U32>}

def v6.dup.con(+g: U32, d: G2) -> G2:
  match d:
    case G2{a, b}:
      G2{Con{g, a}, Con{g, b}}

def v6.dup(gs: List<&2, U32>) -> G2:
  match gs:
    case Nil{}:
      G2{Nil{}, Nil{}}
    case Con{+g, t}:
      v6.dup.con(g, v6.dup(t))

# a run of one group is not compressed
def v6.show.run(r: Run, gs: List<&2, U32>) -> String:
  match r:
    case Run{_, _, +bs, +bl}:
      v6.text(gs, 0, Bool.pick(U32, U32.is_ge(bl, 2), bs, 8), Bool.pick(U32, U32.is_ge(bl, 2), bl, 0), "")

def v6.show.g2(d: G2) -> String:
  match d:
    case G2{a, b}:
      v6.show.run(v6.run(a, 0, Run{0, 0, 0, 0}), b)

# eight groups to their canonical text
def v6.show(gs: List<&2, U32>) -> String:
  v6.show.g2(v6.dup(gs))

def v6.canon.m(m: Maybe<&2, List<&2, U32>>) -> Maybe<&2, String>:
  match m:
    case Some{gs}:
      Some{v6.show(gs)}
    case None{}:
      None{}

# IPv6 text to its canonical text, or None{}: "2001:DB8:0:0::1" and
# "2001:db8::1" both give "2001:db8::1"
def v6.canon(s: String) -> Maybe<&2, String>:
  v6.canon.m(v6.parse(s))

def v6.bytes.m(m: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match m:
    case Some{gs}:
      Some{v6.bytes(gs)}
    case None{}:
      None{}

# IPv6 text to its sixteen bytes, or None{}
def v6.octets(s: String) -> Maybe<&2, List<&2, U32>>:
  v6.bytes.m(v6.parse(s))

# IPv4 parsing
# ------------
# the current part's value and digits, the parts so far (reversed), and
# their count

type S4 is Data:
  S4{part: U32, nd: U32, rev: List<&2, U32>, n: U32}
  S4Bad{}

# a part ends well with one to three digits, no leading zero, at most 255
def v4.part(+part: U32, +nd: U32) -> Bool:
  Bool.and(Bool.and(U32.is_gt(nd, 0), U32.is_le(part, 255)), Bool.or(U32.is_eq(nd, 1), U32.is_ge(part, Bool.pick(U32, U32.is_eq(nd, 2), 10, 100))))

def v4.dot(ok: Bool, +part: U32, rev: List<&2, U32>, +n: U32) -> S4:
  match ok:
    case True{}:
      S4{0, 0, Con{part, rev}, U32.inc(n)}
    case False{}:
      S4Bad{}

def v4.digit(ok: Bool, +part: U32, +nd: U32, rev: List<&2, U32>, +n: U32) -> S4:
  match ok:
    case True{}:
      S4{part, nd, rev, n}
    case False{}:
      S4Bad{}

def v4.c(dot: Bool, +c: U32, +part: U32, +nd: U32, rev: List<&2, U32>, +n: U32) -> S4:
  match dot:
    case True{}:
      v4.dot(Bool.and(v4.part(part, nd), U32.is_lt(n, 3)), part, rev, n)
    case False{}:
      v4.digit(Bool.and(Bool.and(U32.is_ge(c, 48), U32.is_le(c, 57)), U32.is_lt(nd, 3)), U32.add(U32.mul(part, 10), U32.sub(c, 48)), U32.inc(nd), rev, n)

def v4.step(st: S4, +c: U32) -> S4:
  match st:
    case S4{+part, +nd, rev, +n}:
      v4.c(U32.is_eq(c, 46), c, part, nd, rev, n)
    case S4Bad{}:
      S4Bad{}

def v4.end.ok(ok: Bool, +part: U32, rev: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case True{}:
      Some{List.reverse(&2, U32, Con{part, rev})}
    case False{}:
      None{}

def v4.end(st: S4) -> Maybe<&2, List<&2, U32>>:
  match st:
    case S4{+part, +nd, rev, +n}:
      v4.end.ok(Bool.and(v4.part(part, nd), U32.is_eq(n, 3)), part, rev)
    case S4Bad{}:
      None{}

def v4.go(s: String, st: S4) -> Maybe<&2, List<&2, U32>>:
  match s:
    case SNil{}:
      v4.end(st)
    case SCon{Chr{+c}, r}:
      v4.go(r, v4.step(st, c))

# dotted IPv4 text to its four bytes, or None{}
def v4.parse(s: String) -> Maybe<&2, List<&2, U32>>:
  v4.go(s, S4{0, 0, [], 0})

# Literals
# --------

def is_some(m: Maybe<&2, List<&2, U32>>) -> Bool:
  match m:
    case Some{_}:
      True{}
    case None{}:
      False{}

# whether s has a ":" (any IPv6 text does; no host name does)
def has_colon(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{Chr{+c}, r}:
      Bool.or(U32.is_eq(c, 58), has_colon(r))

# whether s is an IPv4 or IPv6 address, not a name to look up
def literal(+s: String) -> Bool:
  Bool.or(is_some(v4.parse(s)), is_some(v6.parse(s)))

def octets.v4(m: Maybe<&2, List<&2, U32>>, +s: String) -> Maybe<&2, List<&2, U32>>:
  match m:
    case Some{b}:
      Some{b}
    case None{}:
      v6.octets(s)

# an IP literal's iPAddress bytes (4 or 16), or None{} for a name
def octets(+s: String) -> Maybe<&2, List<&2, U32>>:
  octets.v4(v4.parse(s), s)

# Address order (dial.bend)
# -------------------------

def max_tries() -> U32:
  8

def attempt_floor_ms() -> U32:
  250

# an attempt's share of what is left, with n addresses still to try
def budget(+left: U32, +n: U32) -> U32:
  Bool.pick(U32, U32.is_le(n, 1), left, U32.max(U32.div(left, n), U32.min(left, attempt_floor_ms())))

type Fam is Data:
  Fam{v6: Bool, scoped: Bool, text: String}

def fam.go(s: String, v6: Bool, scoped: Bool, acc: String) -> Fam:
  match s:
    case SNil{}:
      Fam{v6, scoped, String.reverse(acc)}
    case SCon{Chr{+c}, t}:
      fam.go(t, Bool.or(v6, U32.is_eq(c, 58)), Bool.or(scoped, U32.is_eq(c, 37)), SCon{Chr{c}, acc})

def fam(s: String) -> Fam:
  fam.go(s, False{}, False{}, "")

type Two is Data:
  Two{a: List<&2, String>, b: List<&2, String>}

def same(+x: Bool, +y: Bool) -> Bool:
  Bool.or(Bool.and(x, y), Bool.and(Bool.not(x), Bool.not(y)))

def keep(f: Fam, acc: List<&2, String>) -> List<&2, String>:
  match f:
    case Fam{_, True{}, _}:
      acc
    case Fam{_, False{}, s}:
      Con{s, acc}

# the addresses without a scope (zone), reversed
def unscoped(xs: List<&2, String>, acc: List<&2, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      acc
    case Con{s, t}:
      unscoped(t, keep(fam(s), acc))

def part.side(here: Bool, s: String, a: List<&2, String>, b: List<&2, String>) -> Two:
  match here:
    case True{}:
      Two{Con{s, a}, b}
    case False{}:
      Two{a, Con{s, b}}

def part.put(f: Fam, +first: Bool, a: List<&2, String>, b: List<&2, String>) -> Two:
  match f:
    case Fam{+v6, _, s}:
      part.side(same(v6, first), s, a, b)

def part.two(t: Two, +first: Bool, s: String) -> Two:
  match t:
    case Two{a, b}:
      part.put(fam(s), first, a, b)

# the addresses of the first one's family and the others, each reversed
def part(xs: List<&2, String>, +first: Bool, acc: Two) -> Two:
  match xs:
    case Nil{}:
      acc
    case Con{s, t}:
      part(t, first, part.two(acc, first, s))

def mix.rest(n: Nat, b: List<&2, String>) -> List<&2, String>:
  match n b:
    case 0n _:
      Nil{}
    case 1n+p Nil{}:
      Nil{}
    case 1n+p Con{x, t}:
      Con{x, mix.rest(p, t)}

# a, b, a, b, ... then the rest of the longer, at most n
def mix(n: Nat, a: List<&2, String>, b: List<&2, String>) -> List<&2, String>:
  match n a:
    case 0n _:
      Nil{}
    case 1n+p Con{x, t}:
      Con{x, mix(p, b, t)}
    case 1n+p Nil{}:
      mix.rest(1n+p, b)

def order.two(t: Two) -> List<&2, String>:
  match t:
    case Two{a, b}:
      mix(U32.to_nat(max_tries()), List.reverse(&2, String, a), List.reverse(&2, String, b))

def order.first(f: Fam, t: List<&2, String>) -> List<&2, String>:
  match f:
    case Fam{+v6, _, s}:
      order.two(part(t, v6, Two{[s], []}))

def order.clean(xs: List<&2, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{s, t}:
      order.first(fam(s), t)

# the order to try a lookup's addresses in: scoped ones dropped; the first
# left sets the family that goes first
def order(xs: List<&2, String>) -> List<&2, String>:
  order.clean(List.reverse(&2, String, unscoped(xs, [])))
