import Base
import ./x509_name_match.bend as N
import ./unicode32_nfkc_compose.bend as C
import ./unicode32_nfkc_buffer.bend as B

def key(oid: List<&2, U32>, scalar: U32) -> N.Key:
  N.Key{oid, Array.new(U32, 1n, U32.shln(scalar, 8n)), 1}

def relation(result: N.Key & N.Key & U32) -> U32:
  (_, _, answer) = result
  answer

def equal_key() -> {relation(N.key.compare(key([85,4,3], 97), key([85,4,3], 97))) == 0 : U32}:
  {==}

def OID_binds_key() -> {relation(N.key.compare(key([85,4,3], 97), key([85,4,10], 97))) == 1 : U32}:
  {==}

def scalar_difference() -> {relation(N.key.compare(key([85,4,3], 98), key([85,4,3], 97))) == 2 : U32}:
  {==}

def sorted.equal(a: Maybe<&1, N.Keys()>, b: Maybe<&1, N.Keys()>) -> Bool:
  match a b:
    case Some{a} Some{b}: N.keys.equal(a, b)
    case _ _: False{}

def sorted_same() -> Bool:
  sorted.equal(N.sort(3n, [key([85,4,3],98), key([85,4,10],97), key([85,4,3],97)]),
               N.sort(3n, [key([85,4,3],97), key([85,4,3],98), key([85,4,10],97)]))

def RDN_sort_equivalence() -> {sorted_same() == True{} : Bool}:
  {==}

def repeated_different() -> Bool:
  sorted.equal(N.sort(3n, [key([85,4,3],97), key([85,4,3],97), key([85,4,3],98)]),
               N.sort(3n, [key([85,4,3],97), key([85,4,3],98), key([85,4,3],98)]))

def multiplicity_is_significant() -> {repeated_different() == False{} : Bool}:
  {==}

def empty_RDN_keys() -> {sorted.equal(N.sort(0n, []), Some{[]}) == True{} : Bool}:
  {==}

def failed(value: Maybe<&1, N.Keys()>) -> Bool:
  match value:
    case None{}: True{}
    case Some{_}: False{}

def merge_exhaustion_rejects() -> {failed(N.merge(0n, [key([85,4,3],97)], [key([85,4,3],98)], [])) == True{} : Bool}:
  {==}

def sort_exhaustion_rejects() -> {failed(N.sort.walk(0n, 2n, [key([85,4,3],98), key([85,4,3],97)])) == True{} : Bool}:
  {==}

def reordered_names() -> Bool:
  N.names.equal([[key([85,4,3],97)], [key([85,4,3],98)]],
                [[key([85,4,3],98)], [key([85,4,3],97)]])

def Name_sequence_order() -> {reordered_names() == False{} : Bool}:
  {==}

def partitioned_names() -> Bool:
  N.names.equal([[key([85,4,3],97), key([85,4,3],98)]],
                [[key([85,4,3],97)], [key([85,4,3],98)]])

def Name_RDN_partition() -> {partitioned_names() == False{} : Bool}:
  {==}

def domain_key.normalized(result: C.Normalized) -> N.Key:
  match result:
    case C.Normalized{values, length}: N.Key{[9,146,38,137,147,242,44,100,1,25], values, length}

def domain_key(bytes: List<&2, U32>) -> N.Key:
  domain_key.normalized(N.domain.words(bytes, B.new()))

def domain_ASCII_case() -> {relation(N.key.compare(domain_key([65,66]), domain_key([97,98]))) == 0 : U32}:
  {==}

def domain_controls_retained() -> {relation(N.key.compare(domain_key([65,0]), domain_key([97]))) == 2 : U32}:
  {==}

def domain_spaces_retained() -> {relation(N.key.compare(domain_key([32,65,32]), domain_key([97]))) == 2 : U32}:
  {==}

def domain_empty_sequence() -> {relation(N.key.compare(domain_key([]), domain_key([]))) == 0 : U32}:
  {==}
