import Base
import ./x509_hostname.bend as H

def empty_SAN() -> {H.frame([48,0]) == None{} : Maybe<&1, List<&2, H.Name>>}:
  {==}

def invalid_IP_length() -> {H.frame([48,3,135,1,127]) == None{} : Maybe<&1, List<&2, H.Name>>}:
  {==}

def no_absent_match() -> {H.extensions([48,0],0,[97]) == False{} : Bool}:
  {==}
