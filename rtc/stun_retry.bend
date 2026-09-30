import Base

# RFC 8489 6.2.1. Rc counts the first send; Rm multiplies the INITIAL RTO.
# Bounds keep each OS timeout representable in U32 and the entire schedule
# bounded. ICE requires RTO >= 500 ms (RFC 8445 14.3).
type Policy is Data:
  Policy{rto: U32, requests: U32, final_factor: U32}

def default() -> Policy:
  Policy{500, 7, 16}

def valid(policy: Policy) -> Bool:
  match policy:
    case Policy{+rto, +requests, +factor}:
      Bool.and(Bool.and(U32.is_le(500, rto), U32.is_le(rto, 60000)),
        Bool.and(Bool.and(U32.is_le(1, requests), U32.is_le(requests, 16)),
          Bool.and(U32.is_le(1, factor), U32.is_le(factor, 64))))

def build(left: Nat, +interval: U32, final: U32, reversed: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n:
      List.reverse(&2, U32, Con{final, reversed})
    case 1n+p:
      build(p, (interval * 2 : U32), final, Con{interval, reversed})

def checked(ok: Bool, policy: Policy) -> Maybe<&2, List<&2, U32>>:
  match ok policy:
    case True{} Policy{+rto, requests, factor}:
      Some{build(Nat.sub(U32.to_nat(requests), 1n), rto, (rto * factor : U32), [])}
    case False{} _:
      None{}

# Each element is the wait after a send, including the final response window.
def intervals(+policy: Policy) -> Maybe<&2, List<&2, U32>>:
  checked(valid(policy), policy)
