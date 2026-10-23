import Base
import ./tls_extensions.bend as E
import ./tls_hello.bend as H
import ../crypto/bytes.bend as B

# RFC 9846 handshake framing and extension contexts; RFC 8448 test traces.
# Synthetic-key profile. Bodies remain data; negotiation/authentication belongs
# to the connection owner. Fail contains an RFC alert description, never success.
# Bounds apply before split/copy: 1 MiB encoded handshake, 512 KiB chain,
# at most 16 certificates, at most 65535 DER bytes in each certificate.
type Message is Data:
  ClientHello{hello: H.Hello}
  ServerHello{hello: H.Hello}
  EncryptedExtensions{extensions: List<&2, E.Extension>}
  CertificateRequest{context: List<&2, U32>, extensions: List<&2, E.Extension>}
  Certificate{context: List<&2, U32>, chain: List<&2, List<&2, U32>>}
  CertificateVerify{scheme: U32, signature: List<&2, U32>}
  Finished{verify_data: List<&2, U32>}
  NewSessionTicket{}
  KeyUpdate{request: U32}

def length24(a: U32, b: U32, c: U32) -> Nat:
  Nat.add(Nat.mul(U32.to_nat(a), 65536n), U32.to_nat(E.number(b, c)))

def size16(+size: Nat) -> List<&2, U32>:
  [U32.from_nat(Nat.div(size, 256n)), U32.from_nat(Nat.mod(size, 256n))]

def size24(+size: Nat) -> List<&2, U32>:
  [U32.from_nat(Nat.div(size, 65536n)), U32.from_nat(Nat.mod(Nat.div(size, 256n), 256n)), U32.from_nat(Nat.mod(size, 256n))]

def vector16(+bytes: List<&2, U32>) -> List<&2, U32>:
  B.append(size16(B.length(bytes)), bytes)

def extension(+kind: U32, body: List<&2, U32>) -> List<&2, U32>:
  B.append([U32.shrn(kind, 8n), U32.and(kind, 255)], vector16(body))

def framed(valid: Bool, kind: U32, size: Nat, body: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}: Some{Con{kind, B.append(size24(size), body)}}

def frame(+kind: U32, +body: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  +size = B.length(body)
  framed(Bool.and(U32.is_le(kind, 255), Bool.and(B.valid(body), Nat.is_le(size, 1048572n))), kind, size, body)

# E.take is only called after proving the complete requested vector is present.
def split_checked(valid: Bool, size: Nat, bytes: List<&2, U32>) -> Maybe<&2, E.Parts>:
  match valid:
    case False{}: None{}
    case True{}: E.take(size, bytes, [])

def split(+size: Nat, +bytes: List<&2, U32>) -> Maybe<&2, E.Parts>:
  split_checked(Nat.is_le(size, B.length(bytes)), size, bytes)

def member(+kind: U32, values: List<&2, U32>) -> Bool:
  match values:
    case Nil{}: False{}
    case Con{value, rest}: Bool.or(U32.is_eq(kind, value), member(kind, rest))

# Context numbers: CH=1, SH=2, HRR=6, EE=8, CR=13, CertificateEntry=11,
# NST=4. Known extensions obey the RFC location table; unknown offers remain
# extensible. CertificateRequest and NST are permitted independent extensions.
def allowed(+context: U32, kind: U32) -> Bool:
  match kind:
    case 0: member(context, [1, 8, 13])
    case 1: member(context, [1, 8])
    case 5: member(context, [1, 13, 11])
    case 10: member(context, [1, 8])
    case 13: member(context, [1, 13])
    case 14: member(context, [1, 8])
    case 15: member(context, [1, 8])
    case 16: member(context, [1, 8])
    case 18: member(context, [1, 13, 11])
    case 19: member(context, [1, 8])
    case 20: member(context, [1, 8])
    case 21: U32.is_eq(context, 1)
    case 27: member(context, [1, 13])
    case 28: member(context, [1, 8])
    case 41: member(context, [1, 2])
    case 42: member(context, [1, 8, 4])
    case 43: member(context, [1, 2, 6])
    case 44: member(context, [1, 6])
    case 45: U32.is_eq(context, 1)
    case 47: member(context, [1, 13])
    case 48: U32.is_eq(context, 13)
    case 49: U32.is_eq(context, 1)
    case 50: member(context, [1, 13])
    case 51: member(context, [1, 2, 6])
    case _: Bool.or(U32.is_eq(context, 1), Bool.or(U32.is_eq(context, 8), Bool.or(U32.is_eq(context, 13), U32.is_eq(context, 4))))

def independent(+context: U32, +kind: U32) -> Bool:
  Bool.or(U32.is_eq(context, 1), Bool.or(U32.is_eq(context, 13), Bool.or(U32.is_eq(context, 4),
    Bool.or(Bool.and(U32.is_eq(context, 6), U32.is_eq(kind, 44)),
      Bool.and(U32.is_eq(context, 8), U32.is_eq(kind, 10))))))

def validate_mark(marked: Maybe<&1, Array<U32>>) -> Result<&2, &1, U32, Array<U32>>:
  match marked:
    case None{}: Fail{50}
    case Some{words}: Done{words}

def known(kind: U32) -> Bool:
  member(kind,[0,1,5,10,13,14,15,16,18,19,20,21,27,28,41,42,43,44,45,47,48,49,50,51])

def validate_item(misplaced: Bool, legal: Bool, kind: U32, words: Array<U32>) -> Result<&2, &1, U32, Array<U32>>:
  match misplaced legal:
    case True{} _: Fail{47}
    case False{} False{}: Fail{110}
    case False{} True{}: validate_mark(E.mark(kind, words))

def validate_loop(+context: U32, +offered: List<&2, U32>, values: List<&2, E.Extension>, state: Result<&2, &1, U32, Array<U32>>) -> Maybe<&2, U32>:
  match values state:
    case _ Fail{alert}: Some{alert}
    case Nil{} Done{_}: None{}
    case Con{E.Extension{+kind, _}, rest} Done{words}:
      validate_loop(context, offered, rest, validate_item(Bool.and(known(kind),Bool.not(allowed(context,kind))),
        Bool.and(U32.is_le(kind, 65535), Bool.and(allowed(context, kind),
        Bool.or(independent(context, kind), member(kind, offered)))), kind, words))

def validate_extensions(context: U32, offered: List<&2, U32>, values: List<&2, E.Extension>) -> Maybe<&2, U32>:
  validate_loop(context, offered, values, Done{Array.new(U32, 11n, 0)})

def field_checked(valid: Bool, next: Maybe<&2,U32>) -> Maybe<&2,U32>:
  match valid:
    case False{}: Some{50}
    case True{}: next

def cookie_field(bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Con{a,Con{b,+body}}: Bool.and(Nat.is_gt(B.length(body),0n),Nat.is_eq(U32.to_nat(E.number(a,b)),B.length(body)))
    case _: False{}

def share_field(retry: Bool, bytes: List<&2,U32>) -> Bool:
  match retry bytes:
    case True{} +bytes: Nat.is_eq(B.length(bytes),2n)
    case False{} Con{_,Con{_,Con{a,Con{b,+body}}}}: Nat.is_eq(U32.to_nat(E.number(a,b)),B.length(body))
    case _ _: False{}

def server_fields(+retry: Bool, values: List<&2,E.Extension>) -> Maybe<&2,U32>:
  match values:
    case Nil{}: None{}
    case Con{E.Extension{43,body},rest}: field_checked(Nat.is_eq(B.length(body),2n),server_fields(retry,rest))
    case Con{E.Extension{51,body},rest}: field_checked(share_field(retry,body),server_fields(retry,rest))
    case Con{E.Extension{44,body},rest}: field_checked(cookie_field(body),server_fields(retry,rest))
    case Con{_,rest}: server_fields(retry,rest)

def server_fields_checked(error: Maybe<&2,U32>, random: List<&2,U32>, session: List<&2,U32>, suite: U32, extensions: List<&2,E.Extension>) -> Result<&2,&2,U32,Message>:
  match error:
    case Some{code}: Fail{code}
    case None{}: Done{ServerHello{H.Server{random,session,suite,extensions}}}

def alpn_field(bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Con{a,Con{b,Con{+size,+body}}}:
      Bool.and(U32.is_gt(size,0),Bool.and(Nat.is_eq(U32.to_nat(size),B.length(body)),Nat.is_eq(U32.to_nat(E.number(a,b)),Nat.add(1n,B.length(body)))))
    case _: False{}

def ee_fields(values: List<&2,E.Extension>) -> Maybe<&2,U32>:
  match values:
    case Nil{}: None{}
    case Con{E.Extension{16,body},rest}: field_checked(alpn_field(body),ee_fields(rest))
    case Con{_,rest}: ee_fields(rest)

def ee_fields_checked(error: Maybe<&2,U32>, extensions: List<&2,E.Extension>) -> Result<&2,&2,U32,Message>:
  match error:
    case Some{code}: Fail{code}
    case None{}: Done{EncryptedExtensions{extensions}}

def hello_result(result: Result<&2, &2, H.Error, H.Hello>) -> Result<&2, &2, U32, Message>:
  match result:
    case Fail{H.Version{}}: Fail{70}
    case Fail{H.Compression{}}: Fail{47}
    case Fail{_}: Fail{50}
    case Done{H.Client{random, session, suites, extensions}}:
      Done{ClientHello{H.Client{random, session, suites, extensions}}}
    case Done{H.Server{+random, session, suite, +extensions}}:
      server_fields_checked(server_fields(H.same(random,H.retry_random(),True{}),extensions),random,session,suite,extensions)

def ee(value: Maybe<&2, List<&2, E.Extension>>) -> Result<&2, &2, U32, Message>:
  match value:
    case None{}: Fail{50}
    case Some{+extensions}: ee_fields_checked(ee_fields(extensions),extensions)

def request_extensions(context: List<&2, U32>, value: Maybe<&2, List<&2, E.Extension>>) -> Result<&2, &2, U32, Message>:
  match value:
    case None{}: Fail{50}
    case Some{extensions}: Done{CertificateRequest{context, extensions}}

def request_parts(value: Maybe<&2, E.Parts>) -> Result<&2, &2, U32, Message>:
  match value:
    case None{}: Fail{50}
    case Some{E.Parts{context, rest}}: request_extensions(context, E.parse(rest))

def request(bytes: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match bytes:
    case Con{size, rest}: request_parts(split(U32.to_nat(size), rest))
    case _: Fail{50}

# Certificates are emitted only after every entry's extension vector is parsed
# and validated. This profile offers no server-certificate-entry extensions.
type ChainStep is Data:
  End{}
  Entry{certificate: List<&2, U32>, rest: List<&2, U32>}

def chain_next(error: Maybe<&2, U32>, certificate: List<&2, U32>, rest: List<&2, U32>) -> Result<&2, &2, U32, ChainStep>:
  match error:
    case Some{alert}: Fail{alert}
    case None{}: Done{Entry{certificate, rest}}

def chain_extensions(certificate: List<&2, U32>, rest: List<&2, U32>, value: Maybe<&2, List<&2, E.Extension>>) -> Result<&2, &2, U32, ChainStep>:
  match value:
    case None{}: Fail{50}
    case Some{extensions}: chain_next(validate_extensions(11, [], extensions), certificate, rest)

def chain_extension_parts(certificate: List<&2, U32>, value: Maybe<&2, E.Parts>) -> Result<&2, &2, U32, ChainStep>:
  match value:
    case None{}: Fail{50}
    case Some{E.Parts{bytes, rest}}: chain_extensions(certificate, rest, E.parse(vector16(bytes)))

def chain_certificate_parts(value: Maybe<&2, E.Parts>) -> Result<&2, &2, U32, ChainStep>:
  match value:
    case Some{E.Parts{certificate, Con{high, Con{low, rest}}}}:
      chain_extension_parts(certificate, split(U32.to_nat(E.number(high, low)), rest))
    case _: Fail{50}

def chain_length(valid: Bool, size: Nat, rest: List<&2, U32>) -> Result<&2, &2, U32, ChainStep>:
  match valid:
    case False{}: Fail{50}
    case True{}: chain_certificate_parts(split(size, rest))

def chain_prepare(bytes: List<&2, U32>, count: Nat) -> Result<&2, &2, U32, ChainStep>:
  match bytes:
    case Nil{}: Done{End{}}
    case Con{a, Con{b, Con{c, rest}}}:
      +size = length24(a, b, c)
      chain_length(Bool.and(Nat.is_lt(count, 16n), Bool.and(Nat.is_gt(size, 0n), Nat.is_le(size, 65535n))), size, rest)
    case _: Fail{50}

def chain_loop(budget: Nat, context: List<&2, U32>, step: Result<&2, &2, U32, ChainStep>, reversed: List<&2, List<&2, U32>>, +count: Nat) -> Result<&2, &2, U32, Message>:
  match budget step:
    case _ Fail{alert}: Fail{alert}
    case 0n _: Fail{50}
    case 1n+left Done{End{}}: Done{Certificate{context, List.reverse(&2, List<&2, U32>, reversed)}}
    case 1n+left Done{Entry{certificate, rest}}:
      chain_loop(left, context, chain_prepare(rest, count), Con{certificate, reversed}, Nat.add(count, 1n))

def chain_size(valid: Bool, context: List<&2, U32>, bytes: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match valid:
    case False{}: Fail{50}
    case True{}: chain_loop(17n, context, chain_prepare(bytes, 0n), [], 1n)

def certificate_parts(value: Maybe<&2, E.Parts>) -> Result<&2, &2, U32, Message>:
  match value:
    case Some{E.Parts{context, Con{a, Con{b, Con{c, +rest}}}}}:
      +size = length24(a, b, c)
      chain_size(Bool.and(Nat.is_eq(size, B.length(rest)), Nat.is_le(size, 524288n)), context, rest)
    case _: Fail{50}

def parse_certificate(bytes: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match bytes:
    case Con{size, rest}: certificate_parts(split(U32.to_nat(size), rest))
    case _: Fail{50}

def signature_size(valid: Bool, scheme: U32, signature: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match valid:
    case False{}: Fail{50}
    case True{}: Done{CertificateVerify{scheme, signature}}

def parse_signature(bytes: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match bytes:
    case Con{a, Con{b, Con{high, Con{low, +rest}}}}:
      +size = U32.to_nat(E.number(high, low))
      signature_size(Bool.and(Nat.is_gt(size, 0n), Nat.is_eq(size, B.length(rest))), E.number(a, b), rest)
    case _: Fail{50}

def finished_size(valid: Bool, bytes: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match valid:
    case False{}: Fail{50}
    case True{}: Done{Finished{bytes}}

def ticket_validated(error: Maybe<&2, U32>) -> Result<&2, &2, U32, Message>:
  match error:
    case None{}: Done{NewSessionTicket{}}
    case Some{alert}: Fail{alert}

def ticket_extensions(value: Maybe<&2, List<&2, E.Extension>>) -> Result<&2, &2, U32, Message>:
  match value:
    case None{}: Fail{50}
    case Some{values}: ticket_validated(validate_extensions(4, [], values))

def ticket_value(value: Maybe<&2, E.Parts>) -> Result<&2, &2, U32, Message>:
  match value:
    case None{}: Fail{50}
    case Some{E.Parts{_, rest}}: ticket_extensions(E.parse(rest))

def ticket_length(valid: Bool, size: Nat, rest: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match valid:
    case False{}: Fail{50}
    case True{}: ticket_value(split(size, rest))

def ticket_nonce(value: Maybe<&2, E.Parts>) -> Result<&2, &2, U32, Message>:
  match value:
    case Some{E.Parts{_, Con{high, Con{low, rest}}}}:
      +size = U32.to_nat(E.number(high, low))
      ticket_length(Nat.is_gt(size, 0n), size, rest)
    case _: Fail{50}

def ticket(bytes: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match bytes:
    case Con{_, Con{_, Con{_, Con{_, Con{_, Con{_, Con{_, Con{_, Con{size, rest}}}}}}}}}:
      ticket_nonce(split(U32.to_nat(size), rest))
    case _: Fail{50}

def parse_body(kind: U32, +body: List<&2, U32>, encoded: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match kind:
    case 1: hello_result(H.parse(encoded))
    case 2: hello_result(H.parse(encoded))
    case 4: ticket(body)
    case 8: ee(E.parse(body))
    case 11: parse_certificate(body)
    case 13: request(body)
    case 15: parse_signature(body)
    case 20: finished_size(Nat.is_eq(B.length(body), 32n), body)
    case 24:
      match body:
        case Con{0, Nil{}}: Done{KeyUpdate{0}}
        case Con{1, Nil{}}: Done{KeyUpdate{1}}
        case Con{_, Nil{}}: Fail{47}
        case _: Fail{50}
    case _: Fail{10}

def parse_size(valid: Bool, kind: U32, body: List<&2, U32>, encoded: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match valid:
    case False{}: Fail{50}
    case True{}: parse_body(kind, body, encoded)

def parse_frame(+encoded: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match encoded:
    case Con{kind, Con{a, Con{b, Con{c, +body}}}}:
      parse_size(Nat.is_eq(length24(a, b, c), B.length(body)), kind, body, encoded)
    case _: Fail{50}

def parse_valid(valid: Bool, bytes: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  match valid:
    case False{}: Fail{50}
    case True{}: parse_frame(bytes)

def parse(+bytes: List<&2, U32>) -> Result<&2, &2, U32, Message>:
  parse_valid(Bool.and(B.valid(bytes), Nat.is_le(B.length(bytes), 1048576n)), bytes)

def alert_description(valid: Bool, description: U32) -> Result<&2, &2, U32, U32>:
  match valid:
    case True{}: Done{description}
    case False{}: Fail{50}

def parse_alert(bytes: List<&2, U32>) -> Result<&2, &2, U32, U32>:
  match bytes:
    case Con{1, Con{+description, Nil{}}}: alert_description(U32.is_le(description, 255), description)
    case Con{2, Con{+description, Nil{}}}: alert_description(U32.is_le(description, 255), description)
    case _: Fail{50}

# Serializers take encoded extension items (without the outer vector prefix).
def hello_parsed(value: Maybe<&2,List<&2,E.Extension>>, kind: U32, random: List<&2,U32>, +session: List<&2,U32>, middle: List<&2,U32>, extensions: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match value:
    case None{}: None{}
    case Some{_}: frame(kind, B.append([3,3],B.append(random,Con{U32.from_nat(B.length(session)),B.append(session,B.append(middle,vector16(extensions)))})))

def hello_admitted(valid: Bool, kind: U32, random: List<&2, U32>, +session: List<&2, U32>, middle: List<&2, U32>, +extensions: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}: hello_parsed(E.parse(vector16(extensions)),kind,random,session,middle,extensions)

def hello_client_suites(+random: List<&2,U32>, +session: List<&2,U32>, +suites: List<&2,U32>, +extensions: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  hello_admitted(Bool.and(B.valid(random),Bool.and(B.valid(session),Bool.and(B.valid(suites),Bool.and(B.valid(extensions),
    Bool.and(Nat.is_eq(B.length(random),32n),Bool.and(Nat.is_le(B.length(session),32n),
    Bool.and(Nat.is_ge(B.length(suites),2n),Bool.and(Nat.is_le(B.length(suites),65534n),Bool.and(Nat.is_eq(Nat.mod(B.length(suites),2n),0n),
    Bool.and(Nat.is_ge(B.length(extensions),7n),Nat.is_le(B.length(extensions),65535n))))))))))),
    1,random,session,B.append(vector16(suites),[1,0]),extensions)

def hello_client(random: List<&2,U32>, session: List<&2,U32>, extensions: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  hello_client_suites(random,session,[19,1,19,3],extensions)

def hello_server(+random: List<&2, U32>, +session: List<&2, U32>, +suite: U32, +extensions: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  hello_admitted(Bool.and(U32.is_le(suite, 65535), Bool.and(B.valid(random), Bool.and(B.valid(session), Bool.and(B.valid(extensions),
    Bool.and(Nat.is_eq(B.length(random), 32n), Bool.and(Nat.is_le(B.length(session), 32n), Bool.and(Nat.is_ge(B.length(extensions), 6n), Nat.is_le(B.length(extensions), 65535n)))))))),
    2, random, session, [U32.shrn(suite, 8n), U32.and(suite, 255), 0], extensions)

def extensions_message_parsed(value: Maybe<&2,List<&2,E.Extension>>, kind: U32, prefix: List<&2,U32>, items: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match value:
    case None{}: None{}
    case Some{_}: frame(kind,B.append(prefix,vector16(items)))

def extensions_message(valid: Bool, kind: U32, prefix: List<&2,U32>, +items: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match valid:
    case False{}: None{}
    case True{}: extensions_message_parsed(E.parse(vector16(items)),kind,prefix,items)

def encrypted_extensions(+items: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  extensions_message(Bool.and(B.valid(items),Nat.is_le(B.length(items),65535n)),8,[],items)

def certificate_request(+context: List<&2,U32>, +items: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  extensions_message(Bool.and(B.valid(context),Bool.and(Nat.is_le(B.length(context),255n),Bool.and(B.valid(items),Nat.is_le(B.length(items),65535n)))),
    13,Con{U32.from_nat(B.length(context)),context},items)

def encode_certificate(valid: Bool, cert: List<&2, U32>, size: Nat) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}: Some{B.append([0, 0], B.append(List.reverse(&2, U32, cert), List.reverse(&2, U32, size24(size))))}

def encode_chain_piece(piece: Maybe<&2, List<&2, U32>>, reversed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match piece:
    case None{}: None{}
    case Some{bytes}: Some{B.append(bytes, reversed)}

def encode_chain(values: List<&2, List<&2, U32>>, state: Maybe<&2, List<&2, U32>>, +used: Nat, +count: Nat) -> Maybe<&2, List<&2, U32>>:
  match values state:
    case _ None{}: None{}
    case Nil{} Some{reversed}: Some{List.reverse(&2, U32, reversed)}
    case Con{+cert, rest} Some{reversed}:
      +size = B.length(cert)
      encode_chain(rest, encode_chain_piece(encode_certificate(Bool.and(B.valid(cert), Bool.and(Nat.is_gt(size, 0n), Bool.and(Nat.is_le(size, 65535n),
        Bool.and(Nat.is_lt(count, 16n), Nat.is_le(Nat.add(used, Nat.add(size, 5n)), 524288n))))), cert, size), reversed), Nat.add(used, Nat.add(size, 5n)), Nat.add(count, 1n))

def certificate_encoded(+context: List<&2, U32>, value: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match value:
    case None{}: None{}
    case Some{+bytes}: frame(11, Con{U32.from_nat(B.length(context)), B.append(context, B.append(size24(B.length(bytes)), bytes))})

def certificate_checked(valid: Bool, context: List<&2, U32>, values: List<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}: certificate_encoded(context, encode_chain(values, Some{[]}, 0n, 0n))

def certificate(+context: List<&2, U32>, values: List<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  certificate_checked(Bool.and(B.valid(context), Nat.is_le(B.length(context), 255n)), context, values)

def signature_encoded(valid: Bool, +scheme: U32, signature: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}: frame(15, B.append([U32.shrn(scheme, 8n), U32.and(scheme, 255)], vector16(signature)))

def certificate_verify(+scheme: U32, +signature: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  signature_encoded(Bool.and(U32.is_le(scheme, 65535), Bool.and(B.valid(signature), Bool.and(Nat.is_gt(B.length(signature), 0n), Nat.is_le(B.length(signature), 65535n)))), scheme, signature)

def finished_encoded(valid: Bool, data: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}: frame(20, data)

def finished(+data: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  finished_encoded(Nat.is_eq(B.length(data), 32n), data)

def key_update(request: U32) -> Maybe<&2, List<&2, U32>>:
  match request:
    case 0: frame(24, [0])
    case 1: frame(24, [1])
    case _: None{}

def alert_encoded(valid: Bool, level: U32, description: U32) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}: Some{[level, description]}

def alert(+level: U32, +description: U32) -> Maybe<&2, List<&2, U32>>:
  alert_encoded(Bool.and(member(level, [1, 2]), U32.is_le(description, 255)), level, description)
