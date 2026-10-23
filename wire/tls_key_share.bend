import Base
import ./wire.bend as W
import ../crypto/x25519.bend as X
import ../crypto/p256.bend as P

# One fresh offer per connection (or replacement share after HelloRetryRequest).
# Group identifiers are public; private material remains in a noncopyable owner.
# This is logical one-use ownership, not physical erasure or runtime timing proof.
type Group is Data:
  X25519{}
  P256{}

type Ephemeral is Type:
  XPrivate{scalar: List<&2, U32>}
  PPrivate{scalar: List<&2, U32>}

type Offer is Type:
  Offer{private: Ephemeral, public: List<&2, U32>}

def offered(private: Ephemeral, value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Offer>:
  match value:
    case None{}: None{}
    case Some{public}: Some{Offer{private, public}}

def offered_x(private: Ephemeral, value: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Offer>:
  match value:
    case None{}: None{}
    case Some{public}: Some{Offer{private, public}}

# Pure import of one exact host RNG draw. X25519 clamps in its primitive;
# P-256 uses rejection sampling, never reduction modulo n (which biases it).
# P.public_key validates exactly 32 BE bytes with 1 <= d < n.
def from_random(group: Group, +random: List<&2, U32>) -> Maybe<&1, Offer>:
  match group:
    case X25519{}: offered_x(XPrivate{random}, X.public_key(random))
    case P256{}: offered(PPrivate{random}, P.public_key(random))

# Both success and rejection consume the private owner. X.shared rejects the
# all-zero secret after scanning every output byte; P.shared validates canonical
# uncompressed SEC1 coordinates, curve membership and non-infinity before ECDH.
def shared.x(value: Maybe<&2, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match value:
    case None{}: None{}
    case Some{bytes}: Some{bytes}

def shared(owner: Ephemeral, peer: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match owner:
    case XPrivate{scalar}: shared.x(X.shared(scalar, peer))
    case PPrivate{scalar}: P.shared(scalar, peer)

def retire(owner: Ephemeral) -> Unit:
  match owner:
    case _: Unit{}

# A host failure aborts with no deterministic fallback or retained partial key.
# X25519 draws exactly 32 bytes once. P-256 draws exactly 32 bytes each attempt,
# rejecting 0 and values >= n; 16 attempts bound the effect even on a bad source.
# Failure probability for a functioning uniform RNG is below 2^-512.
def generate.p256_offer(next: IO(Maybe<&1, Offer>), offer: Maybe<&1, Offer>) -> IO(Maybe<&1, Offer>):
  match offer:
    case Some{offer}: IO.pure(Maybe<&1, Offer>, Some{offer})
    case None{}: next

def generate.p256_draw(next: IO(Maybe<&1, Offer>), result: Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Maybe<&1, Offer>):
  match result:
    case Fail{_}: IO.pure(Maybe<&1, Offer>, None{})
    case Done{random}: generate.p256_offer(next, from_random(P256{}, random))

def generate.p256(left: Nat) -> IO(Maybe<&1, Offer>):
  match left:
    case 0n: IO.pure(Maybe<&1, Offer>, None{})
    case 1n+p:
      IO.bind(Result<&1, &1, U32 & String, List<&2, U32>>, Maybe<&1, Offer>,
        W.wire_random_bytes(32), result => generate.p256_draw(generate.p256(p), result))

def generate.x_draw(result: Result<&1, &1, U32 & String, List<&2, U32>>) -> IO(Maybe<&1, Offer>):
  match result:
    case Fail{_}: IO.pure(Maybe<&1, Offer>, None{})
    case Done{random}: IO.pure(Maybe<&1, Offer>, from_random(X25519{}, random))

def generate(group: Group) -> IO(Maybe<&1, Offer>):
  match group:
    case X25519{}:
      IO.bind(Result<&1, &1, U32 & String, List<&2, U32>>, Maybe<&1, Offer>,
        W.wire_random_bytes(32), generate.x_draw)
    case P256{}: generate.p256(16n)
