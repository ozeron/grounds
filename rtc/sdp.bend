import Base
import ./ice_candidates.bend as C
import ./ice_binding.bend as Ice
import ./stun.bend as Stun
import ../utf8/utf8.bend as U
import ../http/core/text.bend as Text

# Bounded offer decoding for one UDP/DTLS/SCTP application section. Unsupported
# media layouts are explicit errors; unsupported candidate transports/addresses
# are ignored, as RFC 8839 5.1 requires. This is not a general SDP implementation.
type Description is Data:
  Description{ufrag: String, password: String, mid: String,
              fingerprint: List<&2, U32>, sctp: U32,
              candidates: List<&2, C.Candidate>, ignored: U32}

type Decoded is Data:
  Valid{description: Description}
  Invalid{reason: String}

type Attribute is Data:
  Attribute{name: String, value: String}

type Document is Data:
  Document{stage: U32, media: Bool, globals: List<&2, Attribute>,
           attributes: List<&2, Attribute>, candidates: List<&2, String>, ok: Bool}

type CandidateRead is Data:
  Accepted{candidate: C.Candidate}
  Skipped{}
  Malformed{}

def bounded(s: String, fuel: Nat) -> Bool:
  match s fuel:
    case SNil{} _: True{}
    case _ 0n: False{}
    case SCon{_, tail} 1n+p: bounded(tail, p)

def visible(s: String, ok: Bool) -> Bool:
  match s:
    case SNil{}: ok
    case SCon{Chr{+c}, tail}:
      visible(tail, Bool.and(ok, Bool.and(U32.is_le(32, c), U32.is_le(c, 126))))

def decimal.step(ok: Bool, value: Nat, again: Nat -> Maybe<&2, U32>) -> Maybe<&2, U32>:
  match ok:
    case True{}: again(value)
    case False{}: None{}

def decimal.go(s: String, fuel: Nat, +value: Nat, +max: Nat) -> Maybe<&2, U32>:
  match s fuel:
    case SNil{} _: Bool.pick(Maybe<&2, U32>, Nat.is_le(value, max), Some{U32.from_nat(value)}, None{})
    case _ 0n: None{}
    case SCon{Chr{+c}, tail} 1n+p:
      decimal.step(Bool.and(U32.is_le(48, c), U32.is_le(c, 57)),
        Nat.add(Nat.mul(value, 10n), Nat.sub(U32.to_nat(c), 48n)), v => decimal.go(tail, p, v, max))

def decimal(s: String, max: Nat) -> Maybe<&2, U32>:
  match s:
    case SNil{}: None{}
    case text: decimal.go(text, 10n, 0n, max)

def hex_digit(c: Char) -> Maybe<&2, U32>:
  match c:
    case Chr{+x}:
      Bool.pick(Maybe<&2, U32>, Ice.between(x, 48, 57), Some{(x - 48 : U32)},
        Bool.pick(Maybe<&2, U32>, Ice.between(x, 65, 70), Some{(x - 55 : U32)},
          Bool.pick(Maybe<&2, U32>, Ice.between(x, 97, 102), Some{(x - 87 : U32)}, None{})))

def hex_pair(a: Maybe<&2, U32>, b: Maybe<&2, U32>) -> Maybe<&2, U32>:
  match a b:
    case Some{x} Some{y}: Some{(x * 16 + y : U32)}
    case _ _: None{}

def fingerprint_byte(s: String) -> Maybe<&2, U32>:
  match s:
    case SCon{a, SCon{b, SNil{}}}: hex_pair(hex_digit(a), hex_digit(b))
    case _: None{}

def fingerprint.more(v: Maybe<&2, U32>, acc: List<&2, U32>,
                     again: List<&2, U32> -> Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match v:
    case Some{n}: again(Con{n, acc})
    case None{}: None{}

def fingerprint.bytes(values: List<&2, String>, fuel: Nat, acc: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match values fuel:
    case Nil{} 0n: Some{List.reverse(&2, U32, acc)}
    case Con{head, tail} 1n+p:
      fingerprint.more(fingerprint_byte(head), acc, a => fingerprint.bytes(tail, p, a))
    case _ _: None{}

def fingerprint.checked(ok: Bool, tail: String) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case True{}: fingerprint.bytes(String.split(tail, ':'), 32n, [])
    case False{}: None{}

def fingerprint.cut(cut: Text.Cut) -> Maybe<&2, List<&2, U32>>:
  match cut:
    case Text.Cut{name, Some{tail}}: fingerprint.checked(Text.same(name, "sha-256", True{}), tail)
    case _: None{}

def fingerprint(s: String) -> Maybe<&2, List<&2, U32>>:
  fingerprint.cut(Text.cut(s, 32))

def extensions(values: List<&2, String>, ok: Bool) -> Bool:
  match values:
    case Nil{}: ok
    case Con{+name, Con{+value, tail}}:
      extensions(tail, Bool.and(ok, Bool.and(Bool.not(String.eq(name, "")), Bool.not(String.eq(value, "")))))
    case _: False{}

def kind.checked(host: Bool, srflx: Bool, prflx: Bool, relay: Bool) -> Maybe<&2, C.Flavor>:
  match host srflx prflx relay:
    case True{} _ _ _: Some{C.Host{}}
    case _ True{} _ _: Some{C.ServerReflexive{}}
    case _ _ True{} _: Some{C.PeerReflexive{}}
    case _ _ _ True{}: Some{C.Relay{}}
    case _ _ _ _: None{}

def kind(+s: String) -> Maybe<&2, C.Flavor>:
  kind.checked(Text.same(s, "host", True{}), Text.same(s, "srflx", True{}),
    Text.same(s, "prflx", True{}), Text.same(s, "relay", True{}))

def host_extensions(values: List<&2, String>, ok: Bool) -> Bool:
  match values:
    case Nil{}: ok
    case Con{+name, Con{+value, tail}}:
      host_extensions(tail, Bool.and(ok, Bool.and(Bool.not(String.eq(name, "raddr")),
        Bool.and(Bool.not(String.eq(name, "rport")), Bool.and(Bool.not(String.eq(name, "")), Bool.not(String.eq(value, "")))))))
    case _: False{}

def related_address(values: List<&2, String>) -> Bool:
  match values:
    case Con{address_name, Con{+host, Con{port_name, Con{port, tail}}}}:
      Bool.and(Text.same(address_name, "raddr", True{}),
        Bool.and(Text.same(port_name, "rport", True{}),
          Bool.and(Bool.not(String.eq(host, "")), Bool.and(Maybe.is_some(&2, U32, decimal(port, 65535n)), extensions(tail, True{})))))
    case _: False{}

def related.kind(k: Maybe<&2, C.Flavor>, values: List<&2, String>) -> Bool:
  match k:
    case Some{C.Host{}}: host_extensions(values, True{})
    case Some{_}: related_address(values)
    case None{}: extensions(values, True{})

def related(k: String, values: List<&2, String>) -> Bool:
  related.kind(kind(k), values)

def candidate.address(address: Maybe<&2, Stun.IPv4>, comp: U32, priority: U32,
                      foundation: String, flavor: C.Flavor) -> CandidateRead:
  match address:
    case Some{a}: Accepted{C.Candidate{comp, priority, foundation, flavor, a}}
    case None{}: Skipped{}

def candidate.checked(ok: Bool, udp: Bool, flavor: Maybe<&2, C.Flavor>, comp: U32,
                      priority: U32, foundation: String, host: String, port: U32) -> CandidateRead:
  match ok udp flavor:
    case False{} _ _: Malformed{}
    case True{} True{} Some{k}: candidate.address(C.address_read(host, port), comp, priority, foundation, k)
    case True{} _ _: Skipped{}

def candidate.numbers(comp: Maybe<&2, U32>, priority: Maybe<&2, U32>, port: Maybe<&2, U32>,
                      +foundation: String, +transport: String, host: String, +k: String,
                      tail: List<&2, String>) -> CandidateRead:
  match comp priority port:
    case Some{+c} Some{+p} Some{+v}:
      candidate.checked(Bool.and(Bool.and(U32.is_le(1, c), U32.is_le(c, 256)),
        Bool.and(Bool.and(U32.is_le(1, p), Bool.and(U32.is_le(1, v), U32.is_le(v, 65535))),
          Bool.and(Ice.credential(U.encode(foundation), 1n, 32n), related(k, tail)))),
        Text.same_ci(transport, "UDP", True{}), kind(k), c, p, foundation, host, v)
    case _ _ _: Malformed{}

def candidate.marker(ok: Bool, f: String, c: String, transport: String, p: String,
                     host: String, port: String, k: String, tail: List<&2, String>) -> CandidateRead:
  match ok:
    case True{}:
      candidate.numbers(decimal(c, 256n), decimal(p, 2147483647n), decimal(port, 65535n), f, transport, host, k, tail)
    case False{}: Malformed{}

def candidate.parts(values: List<&2, String>) -> CandidateRead:
  match values:
    case Con{f, Con{c, Con{transport, Con{p, Con{host, Con{port, Con{marker, Con{k, tail}}}}}}}}:
      candidate.marker(Text.same(marker, "typ", True{}), f, c, transport, p, host, port, k, tail)
    case _: Malformed{}

def candidate(s: String) -> CandidateRead:
  candidate.parts(String.split(s, ' '))

def attribute(cut: Text.Cut) -> Attribute:
  match cut:
    case Text.Cut{name, value}: Attribute{name, Text.or(value, "")}

def add_attribute.checked(candidate: Bool, a: Attribute, doc: Document) -> Document:
  match candidate a doc:
    case True{} Attribute{_, text} Document{stage, True{}, globals, attrs, +candidates, +ok}:
      Document{stage, True{}, globals, attrs, Con{text, candidates}, Bool.and(ok, Nat.is_lt(List.length(&2, String, candidates), 64n))}
    case True{} _ Document{stage, media, globals, attrs, candidates, _}:
      Document{stage, media, globals, attrs, candidates, False{}}
    case False{} value Document{stage, False{}, globals, attrs, candidates, ok}:
      Document{stage, False{}, Con{value, globals}, attrs, candidates, ok}
    case False{} value Document{stage, True{}, globals, attrs, candidates, ok}:
      Document{stage, True{}, globals, Con{value, attrs}, candidates, ok}

def add_attribute(a: Attribute, doc: Document) -> Document:
  match a:
    case Attribute{+name, value}:
      add_attribute.checked(String.eq(name, "candidate"), Attribute{name, value}, doc)

def media_port(port: Maybe<&2, U32>) -> Bool:
  match port:
    case Some{p}: U32.is_gt(p, 0)
    case None{}: False{}

def media_ok(parts: List<&2, String>) -> Bool:
  match parts:
    case [media, port, transport, format]:
      Bool.and(Text.same(media, "application", True{}),
        Bool.and(media_port(decimal(port, 65535n)),
          Bool.and(Text.same(transport, "UDP/DTLS/SCTP", True{}), Text.same(format, "webrtc-datachannel", True{}))))
    case _: False{}

def line.advance(ok: Bool, next: U32, doc: Document) -> Document:
  match ok doc:
    case True{} Document{_, media, g, a, c, valid}: Document{next, media, g, a, c, valid}
    case False{} Document{stage, media, g, a, c, _}: Document{stage, media, g, a, c, False{}}

def line.invalid(doc: Document) -> Document:
  match doc:
    case Document{stage, media, g, a, c, _}: Document{stage, media, g, a, c, False{}}

def line.header(ok: Bool, expected: U32, next: U32, doc: Document) -> Document:
  match doc:
    case Document{+stage, +media, g, a, c, valid}:
      line.advance(Bool.and(ok, Bool.and(U32.is_eq(stage, expected), Bool.not(media))),
        next, Document{stage, media, g, a, c, valid})

def line.media(text: String, doc: Document) -> Document:
  match doc:
    case Document{4, False{}, g, a, c, ok}:
      Document{4, True{}, g, a, c, Bool.and(ok, media_ok(String.split(text, ' ')))}
    case other: line.invalid(other)

def line.attribute(text: String, doc: Document) -> Document:
  match doc:
    case Document{4, media, g, a, c, ok}:
      add_attribute(attribute(Text.cut(text, 58)), Document{4, media, g, a, c, ok})
    case other: line.invalid(other)

def line.field(field: Char, text: String, doc: Document) -> Document:
  match field:
    case 'v': line.header(Text.same(text, "0", True{}), 0, 1, doc)
    case 'o': line.header(True{}, 1, 2, doc)
    case 's': line.header(True{}, 2, 3, doc)
    case 't': line.header(Text.same(text, "0 0", True{}), 3, 4, doc)
    case 'm': line.media(text, doc)
    case 'a': line.attribute(text, doc)
    case 'c': doc
    case 'b': doc
    case 'i': doc
    case 'u': doc
    case 'e': doc
    case 'p': doc
    case _: line.invalid(doc)

def line(s: String, doc: Document) -> Document:
  match s:
    case SCon{field, SCon{'=', text}}: line.field(field, text, doc)
    case _: line.invalid(doc)

def drop_cr(s: String) -> String:
  match s:
    case SCon{'\r', tail}: tail
    case other: other

def clean_line(s: String) -> String:
  String.reverse(drop_cr(String.reverse(s)))

def checked_line(ok: Bool, s: String, doc: Document) -> Document:
  match ok doc:
    case True{} d: line(s, d)
    case False{} Document{stage, media, g, a, c, _}: Document{stage, media, g, a, c, False{}}

def lines(values: List<&2, String>, fuel: Nat, doc: Document) -> Document:
  match values fuel:
    case Nil{} _: doc
    case [""] _: doc
    case Con{head, tail} 1n+p:
      +text = clean_line(head)
      lines(tail, p, checked_line(Bool.and(bounded(text, 1024n), visible(text, True{})), text, doc))
    case _ 0n:
      match doc:
        case Document{stage, media, g, a, c, _}: Document{stage, media, g, a, c, False{}}

type Found is Data:
  Missing{}
  Value{value: String}
  Duplicate{}

def find.keep(hit: Bool, value: String, found: Found) -> Found:
  match hit found:
    case False{} f: f
    case True{} Missing{}: Value{value}
    case True{} _: Duplicate{}

def find(attrs: List<&2, Attribute>, +key: String, found: Found) -> Found:
  match attrs:
    case Nil{}: found
    case Con{Attribute{name, value}, tail}: find(tail, key, find.keep(String.eq(name, key), value, found))

def resolve(media: Found, global: Found) -> Maybe<&2, String>:
  match media global:
    case _ Duplicate{}: None{}
    case Duplicate{} _: None{}
    case Value{v} _: Some{v}
    case Missing{} Value{v}: Some{v}
    case _ _: None{}

def required(+attrs: List<&2, Attribute>, +globals: List<&2, Attribute>, +key: String) -> Maybe<&2, String>:
  resolve(find(attrs, key, Missing{}), find(globals, key, Missing{}))

def complete_candidates.read(read: CandidateRead, acc: List<&2, C.Candidate>, ignored: U32,
                             again: List<&2, C.Candidate> -> U32 -> Decoded) -> Decoded:
  match read:
    case Accepted{c}: again(Con{c, acc}, ignored)
    case Skipped{}: again(acc, (ignored + 1 : U32))
    case Malformed{}: Invalid{"malformed candidate"}

def complete_candidates(values: List<&2, String>, acc: List<&2, C.Candidate>, ignored: U32,
                        uf: String, pwd: String, mid: String, fp: List<&2, U32>, sctp: U32) -> Decoded:
  match values:
    case Nil{}: Valid{Description{uf, pwd, mid, fp, sctp, List.reverse(&2, C.Candidate, acc), ignored}}
    case Con{head, tail}:
      complete_candidates.read(candidate(head), acc, ignored, a => i => complete_candidates(tail, a, i, uf, pwd, mid, fp, sctp))

def complete.checked(ok: Bool, uf: String, pwd: String, mid: String, fp: Maybe<&2, List<&2, U32>>,
                     sctp: Maybe<&2, U32>, candidates: List<&2, String>) -> Decoded:
  match ok fp sctp:
    case True{} Some{f} Some{+p}:
      match p:
        case 0: Invalid{"invalid SCTP port"}
        case _: complete_candidates(candidates, [], 0, uf, pwd, mid, f, p)
    case _ _ _: Invalid{"invalid credentials, MID, fingerprint, setup or SCTP port"}

def complete.values(uf: Maybe<&2, String>, pwd: Maybe<&2, String>, mid: Maybe<&2, String>,
                    fp: Maybe<&2, String>, setup: Maybe<&2, String>, sctp: Maybe<&2, String>, candidates: List<&2, String>) -> Decoded:
  match uf pwd mid fp setup sctp:
    case Some{+u} Some{+p} Some{+m} Some{f} Some{s} Some{c}:
      complete.checked(Bool.and(Bool.and(Ice.credential(U.encode(u), 4n, 256n), Ice.credential(U.encode(p), 22n, 256n)),
        Bool.and(Ice.credential(U.encode(m), 1n, 32n), String.eq(s, "actpass"))), u, p, m, fingerprint(f), decimal(c, 65535n), candidates)
    case _ _ _ _ _ _: Invalid{"missing or duplicate required attribute"}

def complete(doc: Document) -> Decoded:
  match doc:
    case Document{4, True{}, +g, +a, candidates, True{}}:
      complete.values(required(a, g, "ice-ufrag"), required(a, g, "ice-pwd"), required(a, [], "mid"),
        required(a, g, "fingerprint"), required(a, g, "setup"), required(a, [], "sctp-port"), List.reverse(&2, String, candidates))
    case _: Invalid{"invalid or unsupported SDP layout"}

def decode.checked(ok: Bool, s: String) -> Decoded:
  match ok:
    case True{}: complete(lines(String.split(s, '\n'), 128n, Document{0, False{}, [], [], [], True{}}))
    case False{}: Invalid{"SDP exceeds 16384 characters"}

def decode(+s: String) -> Decoded:
  decode.checked(bounded(s, 16384n), s)
