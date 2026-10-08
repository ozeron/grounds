import Base
import ./tls_hello.bend as H

def empty() -> {H.parse([]) == Fail{H.Decode{}} : Result<&2, &2, H.Error, H.Hello>}:
  {==}

def unsupported_kind() -> {H.parse([3, 0, 0, 0]) == Fail{H.Decode{}} : Result<&2, &2, H.Error, H.Hello>}:
  {==}

def short_version() -> {H.parse([1, 0, 0, 1, 3]) == Fail{H.Decode{}} : Result<&2, &2, H.Error, H.Hello>}:
  {==}

def wrong_version() -> {H.parse([1, 0, 0, 2, 3, 4]) == Fail{H.Version{}} : Result<&2, &2, H.Error, H.Hello>}:
  {==}

def nonoctet() -> {H.parse([1, 0, 0, 2, 3, 256]) == Fail{H.Decode{}} : Result<&2, &2, H.Error, H.Hello>}:
  {==}

def odd_suites() -> {H.suites([19], []) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def retry_marker() -> {H.is_retry(H.Server{H.retry_random(), [], 4865, []}) == True{} : Bool}:
  {==}

def client_marker() -> {H.is_retry(H.Client{H.retry_random(), [], [4865], []}) == False{} : Bool}:
  {==}
