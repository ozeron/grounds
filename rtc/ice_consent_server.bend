import Base
import ./ice_consent.bend as Consent
import ./ice_incoming.bend as Incoming
import ./ice_pairs.bend as Pairs
import ./ice_binding.bend as Ice
import ./stun.bend as Stun
import ./stun_auth.bend as Auth
import ./stun_fingerprint.bend as Fingerprint
import ../utf8/utf8.bend as U

# A selected transport's authenticated Binding service. This context has no
# checklist, role, nomination state or permission to grant outbound consent.
type Context is Data:
  Context{secret: Incoming.Secret, remote: String, reference: Pairs.Ref, generation: U32}

type Decision is Data:
  Pass{}
  Reply{bytes: List<&2, U32>, code: U32, transaction: List<&2, U32>, algorithm: Auth.Mode}
  Ignored{}

def ice_attributes(attrs: List<&2, Stun.Attribute>, found: Bool) -> Bool:
  match attrs:
    case Nil{}: found
    case Con{Stun.Attribute{+kind, _}, tail}:
      ice_attributes(tail, Bool.or(found, Bool.or(Bool.or(U32.is_eq(kind, 36), U32.is_eq(kind, 37)),
        Bool.or(U32.is_eq(kind, 32809), U32.is_eq(kind, 32810)))))

def reply_bytes(raw: Maybe<&2, List<&2, U32>>, code: U32, transaction: List<&2, U32>, mode: Auth.Mode) -> Decision:
  match raw:
    case Some{bytes}: Reply{bytes, code, transaction, mode}
    case None{}: Ignored{}

def reply_error(result: Incoming.Decision, transaction: List<&2, U32>, mode: Auth.Mode) -> Decision:
  match result:
    case Incoming.Rejected{bytes, code, _}: Reply{bytes, code, transaction, mode}
    case _: Ignored{}

def error(+transaction: List<&2, U32>, code: U32, unknown: List<&2, U32>, key: List<&2, U32>, +mode: Auth.Mode) -> Decision:
  reply_error(Incoming.reject(transaction, code, unknown, Incoming.Protected{key, mode}), transaction, mode)

def bound(ok: Bool, +transaction: List<&2, U32>, address: Stun.IPv4, +mode: Auth.Mode, key: List<&2, U32>) -> Decision:
  match ok:
    case False{}: error(transaction, 401, [], key, mode)
    case True{}: reply_bytes(Incoming.seal(Incoming.packet(257, transaction, Incoming.mapped(address)), Incoming.Protected{key, mode}), 0, transaction, mode)

def usage(is_ice: Bool, transaction: List<&2, U32>, remote: String, expected: String, address: Stun.IPv4, mode: Auth.Mode, key: List<&2, U32>) -> Decision:
  match is_ice:
    case True{}: Pass{}
    case False{}: bound(String.eq(remote, expected), transaction, address, mode, key)

def understood(unknown: List<&2, U32>, +attrs: List<&2, Stun.Attribute>, transaction: List<&2, U32>, remote: String, expected: String,
               address: Stun.IPv4, mode: Auth.Mode, key: List<&2, U32>) -> Decision:
  match unknown:
    case Nil{}: usage(ice_attributes(attrs, False{}), transaction, remote, expected, address, mode, key)
    case Con{head, tail}: error(transaction, 420, Con{head, tail}, key, mode)

def authenticated(packet: Maybe<&2, Stun.Packet>, transaction: List<&2, U32>, remote: String, expected: String, address: Stun.IPv4,
                  mode: Auth.Mode, key: List<&2, U32>) -> Decision:
  match packet:
    case None{}: Ignored{}
    case Some{Stun.Packet{_, _, +attrs}}:
      understood(Incoming.unknowns(attrs, []), attrs, transaction, remote, expected, address, mode, key)

def named(remote: Maybe<&2, String>, +raw: List<&2, U32>, transaction: List<&2, U32>, +secret: Incoming.Secret, expected: String,
          address: Stun.IPv4, mode: Auth.Mode) -> Decision:
  match remote:
    case None{}: Ignored{}
    case Some{r}: authenticated(Auth.authenticate(raw, Incoming.key(secret), Auth.Dual{}), transaction, r, expected, address, mode, Incoming.key(secret))

def username(value: Maybe<&2, List<&2, U32>>, raw: List<&2, U32>, transaction: List<&2, U32>, secret: Incoming.Secret, expected: String,
             address: Stun.IPv4, mode: Auth.Mode) -> Decision:
  match value secret:
    case Some{bytes} Incoming.Secret{+local, password}:
      named(Incoming.username_parts(bytes, U.encode(local), []), raw, transaction, Incoming.Secret{local, password}, expected, address, mode)
    case _ _: Ignored{}

def layout(found: Maybe<&2, Auth.Layout>, raw: List<&2, U32>, transaction: List<&2, U32>, secret: Incoming.Secret, expected: String,
           address: Stun.IPv4) -> Decision:
  match found:
    case Some{Auth.Layout{_, +sha256, attrs, _}}:
      username(Incoming.first(attrs, 6), raw, transaction, secret, expected, address, Auth.algorithm(sha256))
    case None{}: Ignored{}

def parsed(packet: Maybe<&2, Stun.Packet>, raw: List<&2, U32>, context: Context) -> Decision:
  match packet context:
    case Some{Stun.Packet{1, tx, attrs}} Context{secret, remote, Pairs.Ref{_, _, _, address}, _}:
      layout(Auth.layout(attrs, 0n, 0, Auth.Missing{}, Auth.Missing{}, []), raw, tx, secret, remote, address)
    case _ _: Pass{}

def checked(ok: Bool, +raw: List<&2, U32>, context: Context) -> Decision:
  match ok:
    case False{}: Ignored{}
    case True{}: parsed(Stun.parse(raw), raw, context)

# Metadata is supplied by the actual receiving socket. Known selected aliases
# must be resolved to this context's reference by their transport owner.
def receive(+raw: List<&2, U32>, context: Context, actual: Pairs.Ref) -> Decision:
  match context:
    case Context{+secret, +remote, +reference, generation}:
      checked(Bool.and(Bool.and(Pairs.same(reference, actual), Incoming.secret_valid(secret)),
        Bool.and(Ice.credential(U.encode(remote), 4n, 256n), Fingerprint.verify(raw))),
        raw, Context{secret, remote, reference, generation})
