import Base

# Shared fixture helpers; CLI adapters keep forwarding definitions.

def Entropy() -> Type:
  Result<&1, &1, U32 & String, U32 & U32 & U32>

def random_third(c: Result<&1, &1, U32 & String, U32>, a: U32, b: U32) -> IO(Entropy()):
  match c:
    case Done{c}: IO.pure(Entropy(), Done{(a, (b, c))})
    case Fail{error}: IO.pure(Entropy(), Fail{error})

def random_second(b: Result<&1, &1, U32 & String, U32>, a: U32) -> IO(Entropy()):
  match b:
    case Done{b}: IO.bind(Result<&1, &1, U32 & String, U32>, Entropy(), IO.random_u32(), c => random_third(c, a, b))
    case Fail{error}: IO.pure(Entropy(), Fail{error})

def random_first(a: Result<&1, &1, U32 & String, U32>) -> IO(Entropy()):
  match a:
    case Done{a}: IO.bind(Result<&1, &1, U32 & String, U32>, Entropy(), IO.random_u32(), b => random_second(b, a))
    case Fail{error}: IO.pure(Entropy(), Fail{error})

def random() -> IO(Entropy()):
  IO.bind(Result<&1, &1, U32 & String, U32>, Entropy(), IO.random_u32(), a => random_first(a))
