import Base
import ./sha256.bend as Sha
import ./LAWS.bend as Laws

def Laws.sha256_output_length(s):
  match s:
    case Sha.State{_, _, _, _, _, _, _, _}:
      {==}
