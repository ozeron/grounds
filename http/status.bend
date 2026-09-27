import Base

# a response status (RFC 9110 §15): a three-digit code
type Status is Data:
  Status{code: U32}

def ok() -> Status:
  Status{200}

def created() -> Status:
  Status{201}

def no_content() -> Status:
  Status{204}

def moved_permanently() -> Status:
  Status{301}

def found() -> Status:
  Status{302}

def see_other() -> Status:
  Status{303}

def not_modified() -> Status:
  Status{304}

def bad_request() -> Status:
  Status{400}

def unauthorized() -> Status:
  Status{401}

def forbidden() -> Status:
  Status{403}

def not_found() -> Status:
  Status{404}

def method_not_allowed() -> Status:
  Status{405}

def request_timeout() -> Status:
  Status{408}

def content_too_large() -> Status:
  Status{413}

def unsupported_media_type() -> Status:
  Status{415}

def header_fields_too_large() -> Status:
  Status{431}

def internal_error() -> Status:
  Status{500}

def not_implemented() -> Status:
  Status{501}

def service_unavailable() -> Status:
  Status{503}

def version_not_supported() -> Status:
  Status{505}

def code(s: Status) -> U32:
  match s:
    case Status{c}:
      c

# the reason phrase HTTP/1.1 writes after the code (RFC 9110 §15)
def reason(s: Status) -> String:
  match s:
    case Status{200}:
      "OK"
    case Status{201}:
      "Created"
    case Status{204}:
      "No Content"
    case Status{301}:
      "Moved Permanently"
    case Status{302}:
      "Found"
    case Status{303}:
      "See Other"
    case Status{304}:
      "Not Modified"
    case Status{400}:
      "Bad Request"
    case Status{401}:
      "Unauthorized"
    case Status{403}:
      "Forbidden"
    case Status{404}:
      "Not Found"
    case Status{405}:
      "Method Not Allowed"
    case Status{408}:
      "Request Timeout"
    case Status{413}:
      "Content Too Large"
    case Status{415}:
      "Unsupported Media Type"
    case Status{431}:
      "Request Header Fields Too Large"
    case Status{500}:
      "Internal Server Error"
    case Status{501}:
      "Not Implemented"
    case Status{503}:
      "Service Unavailable"
    case Status{505}:
      "HTTP Version Not Supported"
    case _:
      ""
