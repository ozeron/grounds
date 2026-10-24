import Base
import ./x509_algorithm.bend as A
import ./x509_certificate.bend as C

def sha384_rsa() -> {A.signature([48,11,6,9,42,134,72,134,247,13,1,1,12]) == Some{A.RsaV15384{}} : Maybe<&1,A.Signature>}:
  {==}

def sha384_ecdsa() -> {A.signature([48,10,6,8,42,134,72,206,61,4,3,3]) == Some{A.Ecdsa384{}} : Maybe<&1,A.Signature>}:
  {==}

def pss_salts_must_match() -> {C.same_algorithm(A.RsaPss384{48},A.RsaPss384{47}) == False{} : Bool}:
  {==}

def pss_key_never_v15() -> {A.compatible(A.Pss384{48},A.RsaV15384{}) == False{} : Bool}:
  {==}
