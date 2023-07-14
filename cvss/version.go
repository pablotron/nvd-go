package cvss

import "fmt"

// CVSS version
type Version byte

const (
  UnknownVersion Version = iota
  V2
  V30
  V31
  // V4
)

var versions = map[string]Version {
  "2.0": V2,
  "3.0": V30,
  "3.1": V31,
}

// parse version string
func ParseVersion(s string) (*Version, error) {
  if v, ok := versions[s]; ok {
    return &v, nil
  } else {
    return nil, fmt.Errorf("unknown CVSS version: %s", s)
  }
}

func (v Version) String() string {
  switch v {
  case V2:
    return "2.0"
  case V30:
    return "3.0"
  case V31:
    return "3.1"
  default:
    return ""
  }
}

// Is this a valid severity for the given CVSS version?
func (v Version) ValidSeverity(s Severity) bool {
  switch v {
  case V2:
    return s == Low || s == Medium || s == High
  case V30:
    return s == Low || s == Medium || s == High || s == Critical
  case V31:
    return s == Low || s == Medium || s == High || s == Critical
  default:
    return false
  }
}
