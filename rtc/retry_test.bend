import Base
import ./stun_retry.bend as Retry

# Published RFC 8489 schedule: send at 0/500/1500/3500/7500/15500/31500,
# timeout at 39500. Final wait is 16 * initial RTO, NOT current backoff.
def standard_schedule() -> {Retry.intervals(Retry.default()) ==
  Some{[500, 1000, 2000, 4000, 8000, 16000, 8000]} : Maybe<&2, List<&2, U32>>}:
  {==}

def one_send_final_window() -> {Retry.intervals(Retry.Policy{1000, 1, 16}) ==
  Some{[16000]} : Maybe<&2, List<&2, U32>>}:
  {==}

def reject_ice_rto() -> {Retry.intervals(Retry.Policy{499, 7, 16}) ==
  None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def reject_zero_requests() -> {Retry.intervals(Retry.Policy{500, 0, 16}) ==
  None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def reject_large_schedule() -> {Retry.intervals(Retry.Policy{60000, 17, 64}) ==
  None{} : Maybe<&2, List<&2, U32>>}:
  {==}
