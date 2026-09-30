import Base
import ./ice_binding.bend as Ice
import ./ice_roles.bend as Roles
import ./ice_candidates.bend as C
import ./ice_response.bend as Response
import ./stun.bend as Stun
import ./stun_auth.bend as Auth
import ./stun_fingerprint.bend as Fingerprint
import ../crypto/bytes.bend as B
import ../utf8/utf8.bend as U

# Local session credentials suffice before receiving the remote answer. The
# session owner removes/rotates them on restart or expiry and binds peer details.
type Secret is Data:
  Secret{ufrag: String, password: String}

type Request is Data:
  Request{transaction: List<&2, U32>, remote: String, priority: U32, role: Ice.Role, nominate: Bool, algorithm: Auth.Mode}

type Decision is Data:
  Accepted{reply: List<&2, U32>, request: Request, role: Ice.Role, switched: Bool}
  Rejected{reply: List<&2, U32>, code: U32, authenticated: Bool}
  Ignored{}
  InvalidInput{}

type Protection is Data:
  Plain{}
  Protected{key: List<&2, U32>, algorithm: Auth.Mode}

def secret_valid(secret: Secret) -> Bool:
  match secret:
    case Secret{ufrag, password}:
      Bool.and(Ice.credential(U.encode(ufrag), 4n, 32n), Ice.credential(U.encode(password), 22n, 256n))

def key(secret: Secret) -> List<&2, U32>:
  match secret:
    case Secret{_, password}: U.encode(password)

def first(attrs: List<&2, Stun.Attribute>, +wanted: U32) -> Maybe<&2, List<&2, U32>>:
  match attrs:
    case Nil{}: None{}
    case Con{Stun.Attribute{+kind, +value}, tail}:
      Bool.pick(Maybe<&2, List<&2, U32>>, U32.is_eq(kind, wanted), Some{value}, first(tail, wanted))

def header(raw: Maybe<&2, List<&2, U32>>, +kind: U32, body: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match raw:
    case Some{Con{_, Con{_, tail}}}:
      Ice.unsigned_header(Some{Con{U32.shrn(kind, 8n), Con{U32.and(kind, 255), tail}}}, body)
    case _: None{}

def packet(kind: U32, transaction: List<&2, U32>, body: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  header(Stun.binding_request(transaction), kind, body)

def seal(raw: Maybe<&2, List<&2, U32>>, protection: Protection) -> Maybe<&2, List<&2, U32>>:
  match raw protection:
    case None{} _: None{}
    case Some{bytes} Plain{}: Auth.fingerprint(Some{bytes})
    case Some{bytes} Protected{key, mode}: Auth.sign(bytes, key, mode)

def phrase(code: U32) -> String:
  match code:
    case 400: "Bad Request"
    case 401: "Unauthenticated"
    case 420: "Unknown Attribute"
    case 487: "Role Conflict"
    case _: "Error"

def unknown_bytes(kinds: List<&2, U32>, reversed: List<&2, U32>) -> List<&2, U32>:
  match kinds:
    case Nil{}: List.reverse(&2, U32, reversed)
    case Con{+kind, tail}:
      unknown_bytes(tail, Con{U32.and(kind, 255), Con{U32.shrn(kind, 8n), reversed}})

def error_extra(unknown: List<&2, U32>, error: List<&2, U32>) -> List<&2, U32>:
  match unknown:
    case Nil{}: error
    case Con{head, tail}: B.append(error, Ice.attribute(10, unknown_bytes(Con{head, tail}, [])))

def error_body(+code: U32, unknown: List<&2, U32>) -> List<&2, U32>:
  error_extra(unknown, Ice.attribute(9, B.append([0, 0, (code / 100 : U32), (code % 100 : U32)], U.encode(phrase(code)))))

def rejected(raw: Maybe<&2, List<&2, U32>>, code: U32, authenticated: Bool) -> Decision:
  match raw:
    case None{}: InvalidInput{}
    case Some{bytes}: Rejected{bytes, code, authenticated}

def protected(protection: Protection) -> Bool:
  match protection:
    case Plain{}: False{}
    case Protected{_, _}: True{}

def reject(transaction: List<&2, U32>, +code: U32, unknown: List<&2, U32>, +protection: Protection) -> Decision:
  rejected(seal(packet(273, transaction, error_body(code, unknown)), protection), code, protected(protection))

def mapped(address: Stun.IPv4) -> List<&2, U32>:
  match address:
    case Stun.IPv4{a, b, c, d, +port}:
      Ice.attribute(32, B.append([0, 1], B.append(
        [U32.shrn(U32.xor(port, 8466), 8n), U32.and(U32.xor(port, 8466), 255)],
        [U32.xor(a, 33), U32.xor(b, 18), U32.xor(c, 164), U32.xor(d, 66)])))

def accepted(raw: Maybe<&2, List<&2, U32>>, request: Request, role: Ice.Role, switched: Bool) -> Decision:
  match raw:
    case None{}: InvalidInput{}
    case Some{reply}: Accepted{reply, request, role, switched}

def resolved(resolution: Roles.Resolution, request: Request, address: Stun.IPv4, key: List<&2, U32>) -> Decision:
  match resolution request:
    case Roles.Conflict{} Request{transaction, _, _, _, _, mode}:
      reject(transaction, 487, [], Protected{key, mode})
    case Roles.Keep{local} Request{+transaction, +remote, +priority, +role, +nominate, +mode}:
      accepted(seal(packet(257, transaction, mapped(address)), Protected{key, mode}),
        Request{transaction, remote, priority, role, nominate, mode}, local, False{})
    case Roles.Switch{local} Request{+transaction, +remote, +priority, +role, +nominate, +mode}:
      accepted(seal(packet(257, transaction, mapped(address)), Protected{key, mode}),
        Request{transaction, remote, priority, role, nominate, mode}, local, True{})

def word(bytes: Maybe<&2, List<&2, U32>>) -> Maybe<&2, U32>:
  match bytes:
    case Some{[a, b, c, d]}: Some{U32.or(U32.or(U32.or(U32.shln(a, 24n), U32.shln(b, 16n)), U32.shln(c, 8n)), d)}
    case _: None{}

def tie_words(bytes: List<&2, U32>, controlling: Bool) -> Maybe<&2, Ice.Role>:
  match bytes:
    case [+a, +b, +c, +d, +e, +f, +g, +h]:
      Some{Bool.pick(Ice.Role, controlling,
        Ice.Controlling{U32.or(U32.or(U32.or(U32.shln(a, 24n), U32.shln(b, 16n)), U32.shln(c, 8n)), d),
                        U32.or(U32.or(U32.or(U32.shln(e, 24n), U32.shln(f, 16n)), U32.shln(g, 8n)), h)},
        Ice.Controlled{U32.or(U32.or(U32.or(U32.shln(a, 24n), U32.shln(b, 16n)), U32.shln(c, 8n)), d),
                       U32.or(U32.or(U32.or(U32.shln(e, 24n), U32.shln(f, 16n)), U32.shln(g, 8n)), h)})}
    case _: None{}

def peer_role(controlling: Maybe<&2, List<&2, U32>>, controlled: Maybe<&2, List<&2, U32>>) -> Maybe<&2, Ice.Role>:
  match controlling controlled:
    case Some{bytes} None{}: tie_words(bytes, True{})
    case None{} Some{bytes}: tie_words(bytes, False{})
    case _ _: None{}

def nomination(bytes: Maybe<&2, List<&2, U32>>) -> Maybe<&2, Bool>:
  match bytes:
    case None{}: Some{False{}}
    case Some{Nil{}}: Some{True{}}
    case _: None{}

def fields_valid(ok: Bool, +transaction: List<&2, U32>, remote: String, priority: U32, +peer: Ice.Role,
                 nominate: Bool, +mode: Auth.Mode, local: Ice.Role, address: Stun.IPv4, +key: List<&2, U32>) -> Decision:
  match ok:
    case False{}: reject(transaction, 400, [], Protected{key, mode})
    case True{}:
      resolved(Roles.resolve(local, peer), Request{transaction, remote, priority, peer, nominate, mode}, address, key)

def fields(priority: Maybe<&2, U32>, peer: Maybe<&2, Ice.Role>, nominate: Maybe<&2, Bool>, transaction: List<&2, U32>,
           remote: String, mode: Auth.Mode, local: Ice.Role, address: Stun.IPv4, key: List<&2, U32>) -> Decision:
  match priority peer nominate:
    case Some{+p} Some{+r} Some{+n}:
      fields_valid(Bool.and(Bool.and(U32.is_le(1, p), U32.is_le(p, 2147483647)),
        Bool.or(Bool.not(n), Roles.controlling(r))), transaction, remote, p, r, n, mode, local, address, key)
    case _ _ _: reject(transaction, 400, [], Protected{key, mode})

def unknowns(attrs: List<&2, Stun.Attribute>, +reversed: List<&2, U32>) -> List<&2, U32>:
  match attrs:
    case Nil{}: List.reverse(&2, U32, reversed)
    case Con{Stun.Attribute{+kind, _}, tail}:
      unknowns(tail, Bool.pick(List<&2, U32>, Bool.and(U32.is_lt(kind, 32768), Bool.not(Response.known(kind))), Con{kind, reversed}, reversed))

def understood(unknown: List<&2, U32>, +attrs: List<&2, Stun.Attribute>, transaction: List<&2, U32>, remote: String,
               mode: Auth.Mode, local: Ice.Role, address: Stun.IPv4, key: List<&2, U32>) -> Decision:
  match unknown:
    case Nil{}:
      fields(word(first(attrs, 36)), peer_role(first(attrs, 32810), first(attrs, 32809)), nomination(first(attrs, 37)),
        transaction, remote, mode, local, address, key)
    case Con{head, tail}: reject(transaction, 420, Con{head, tail}, Protected{key, mode})

def authenticated(packet: Maybe<&2, Stun.Packet>, transaction: List<&2, U32>, remote: String,
                  mode: Auth.Mode, local: Ice.Role, address: Stun.IPv4, key: List<&2, U32>) -> Decision:
  match packet:
    case None{}: reject(transaction, 401, [], Plain{})
    case Some{Stun.Packet{_, _, +attrs}}:
      understood(unknowns(attrs, []), attrs, transaction, remote, mode, local, address, key)

def decoded(text: U.Text) -> Maybe<&2, String>:
  match text:
    case U.TOk{value}: Some{value}
    case _: None{}

def username_text(valid: Bool, remote: List<&2, U32>) -> Maybe<&2, String>:
  match valid:
    case False{}: None{}
    case True{}: decoded(U.decode(remote))

def username_parts(got: List<&2, U32>, local: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<&2, String>:
  match got:
    case Nil{}: None{}
    case Con{58, +remote}:
      username_text(Bool.and(Stun.same(List.reverse(&2, U32, reversed), local, True{}), Ice.credential(remote, 4n, 256n)), remote)
    case Con{byte, tail}: username_parts(tail, local, Con{byte, reversed})

def username_found(remote: Maybe<&2, String>, +raw: List<&2, U32>, transaction: List<&2, U32>,
                   +secret: Secret, mode: Auth.Mode, local: Ice.Role, address: Stun.IPv4) -> Decision:
  match remote:
    case None{}: reject(transaction, 401, [], Plain{})
    case Some{r}: authenticated(Auth.authenticate(raw, key(secret), Auth.Dual{}), transaction, r, mode, local, address, key(secret))

def integrity_found(mac: Auth.Mac, username: List<&2, U32>, raw: List<&2, U32>, transaction: List<&2, U32>,
                    +ufrag: String, password: String, mode: Auth.Mode, local: Ice.Role, address: Stun.IPv4) -> Decision:
  match mac:
    case Auth.Missing{}: reject(transaction, 400, [], Plain{})
    case Auth.Mac{_, _}:
      username_found(username_parts(username, U.encode(ufrag), []), raw, transaction,
        Secret{ufrag, password}, mode, local, address)

def named(username: Maybe<&2, List<&2, U32>>, legacy: Auth.Mac, +sha256: Auth.Mac,
          raw: List<&2, U32>, transaction: List<&2, U32>, ufrag: String, password: String,
          local: Ice.Role, address: Stun.IPv4) -> Decision:
  match username:
    case None{}: reject(transaction, 400, [], Plain{})
    case Some{u}:
      integrity_found(Auth.selected(Auth.Dual{}, legacy, sha256), u, raw, transaction,
        ufrag, password, Auth.algorithm(sha256), local, address)

def layout(found: Maybe<&2, Auth.Layout>, raw: List<&2, U32>, transaction: List<&2, U32>,
           secret: Secret, local: Ice.Role, address: Stun.IPv4) -> Decision:
  match found secret:
    case Some{Auth.Layout{legacy, sha256, attrs, _}} Secret{ufrag, password}:
      named(first(attrs, 6), legacy, sha256, raw, transaction, ufrag, password, local, address)
    case _ _: reject(transaction, 400, [], Plain{})

def parsed(packet: Maybe<&2, Stun.Packet>, +raw: List<&2, U32>, secret: Secret, local: Ice.Role, address: Stun.IPv4) -> Decision:
  match packet:
    case Some{Stun.Packet{1, transaction, attrs}}:
      layout(Auth.layout(attrs, 0n, 0, Auth.Missing{}, Auth.Missing{}, []), raw, transaction, secret, local, address)
    case _: Ignored{}

def checked(valid: Bool, +raw: List<&2, U32>, secret: Secret, local: Ice.Role, address: Stun.IPv4) -> Decision:
  match valid:
    case True{}: parsed(Stun.parse(raw), raw, secret, local, address)
    case False{}: Ignored{}

def configured(valid: Bool, +raw: List<&2, U32>, secret: Secret, local: Ice.Role, address: Stun.IPv4) -> Decision:
  match valid:
    case True{}: checked(Fingerprint.verify(raw), raw, secret, local, address)
    case False{}: InvalidInput{}

# Source must be the observed transport peer, not an address claimed in STUN.
# Only Accepted exposes authenticated metadata. Replies always end with CRC;
# authentication failures produce unsigned errors and never authorize state.
def receive(+raw: List<&2, U32>, +secret: Secret, local: Ice.Role, +source: Stun.IPv4) -> Decision:
  configured(Bool.and(secret_valid(secret), C.address_valid(source)), raw, secret, local, source)
