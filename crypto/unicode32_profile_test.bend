import Base
import ./unicode32_profile.bend as P

def variation_selector_removed() -> {P.map_code(65024) == P.Removed{} : P.Mapping}:
  {==}

def fullwidth_block_not_removed() -> {P.map_code(65280) == P.Mapped{65280} : P.Mapping}:
  {==}

def tab_maps_to_space() -> {P.map_code(9) == P.Mapped{32} : P.Mapping}:
  {==}

def zero_width_space_removed() -> {P.map_code(8203) == P.Removed{} : P.Mapping}:
  {==}

def surrogate_is_invalid() -> {P.map_code(55296) == P.Invalid{} : P.Mapping}:
  {==}

def outside_Unicode_is_invalid() -> {P.map_code(1114112) == P.Invalid{} : P.Mapping}:
  {==}

def replacement_not_deleted() -> {P.map_code(65533) == P.Mapped{65533} : P.Mapping}:
  {==}

def replacement_prohibited_after_normalization() -> {P.prohibited.fixed(65533) == True{} : Bool}:
  {==}
