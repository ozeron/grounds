import Base
import ./ice_binding.bend as Ice

type Resolution is Data:
  Keep{role: Ice.Role}
  Switch{role: Ice.Role}
  Conflict{}

def controlling(role: Ice.Role) -> Bool:
  match role:
    case Ice.Controlling{_, _}: True{}
    case Ice.Controlled{_, _}: False{}

def at_least(+high: U32, low: U32, +other_high: U32, other_low: U32) -> Bool:
  Bool.or(U32.is_gt(high, other_high), Bool.and(U32.is_eq(high, other_high), U32.is_le(other_low, low)))

def controlling_conflict(own_wins: Bool, high: U32, low: U32) -> Resolution:
  match own_wins:
    case True{}: Conflict{}
    case False{}: Switch{Ice.Controlled{high, low}}

def controlled_conflict(own_wins: Bool, high: U32, low: U32) -> Resolution:
  match own_wins:
    case True{}: Switch{Ice.Controlling{high, low}}
    case False{}: Conflict{}

# RFC 8445 7.3.1.1. The receiver keeps its own tie-breaker on a role switch;
# its agent must recompute pair priorities before scheduling another check.
def resolve(local: Ice.Role, remote: Ice.Role) -> Resolution:
  match local remote:
    case Ice.Controlling{+high, +low} Ice.Controlling{rh, rl}:
      controlling_conflict(at_least(high, low, rh, rl), high, low)
    case Ice.Controlled{+high, +low} Ice.Controlled{rh, rl}:
      controlled_conflict(at_least(high, low, rh, rl), high, low)
    case l _: Keep{l}
