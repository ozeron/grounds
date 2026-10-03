import Base
import ./unicode32_fold.bend as F
import ./unicode32_fold_cli.bend as C

# Run the larger expansion separately from the exhaustive output matrix.
def main() -> IO(Unit):
  C.stress(F.string(F.tables(), C.repeat(65535n, []), True{}))
