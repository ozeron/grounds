import Base

type Json is Data:
  JNull{}
  JBool{value: Bool}
  JNum{value: F32}
  JStr{value: String}
  JArr{items: List<&2, Json>}
  JObj{fields: List<&2, Field>}

type Field is Data:
  Field{key: String, value: Json}

def is_null(j: Json) -> Bool:
  match j:
    case JNull{}:
      True{}
    case _:
      False{}
