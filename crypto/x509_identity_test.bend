import Base
import ./x509_identity.bend as H

def wildcard_one_label() -> {H.dns([42,46,97,46,98], [120,46,97,46,98]) == True{} : Bool}:
  {==}

def wildcard_not_two() -> {H.dns([42,46,97,46,98], [120,46,121,46,97,46,98]) == False{} : Bool}:
  {==}

def exact_case() -> {H.dns([65,46,66], [97,46,98]) == True{} : Bool}:
  {==}

def invalid_reference() -> {H.dns([97], [353]) == False{} : Bool}:
  {==}

def no_ip_family_alias() -> {H.ip([127,0,0,1], [0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,1]) == False{} : Bool}:
  {==}

def invalid_ip_byte() -> {H.ip([127,0,0,257], [127,0,0,257]) == False{} : Bool}:
  {==}
