package cvss

import "fmt"

// CVSS version
type Version byte

const (
  UnknownVersion Version = iota
  V2 // CVSS 2
  V30 // CVSS v3.0
  V31 // CVSS v3.1
  // TODO: V4
)

// Version string to version map.
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

// Unmarshal CVSS version from text.
func (v *Version) UnmarshalText(b []byte) error {
  s := string(b)
  if nv, err := ParseVersion(s); err == nil {
    *v = *nv
    return nil
  } else {
    return err
  }
}

// Version strings.  used by `String()`.
var versionStrs = [...]string {
  "",
  "2.0",
  "3.0",
  "3.1",
}

// Convert CVSS version to string.  Returns "" if the given version
// string is not valid.
func (v Version) String() string {
  if int(v) < len(versionStrs) {
    return versionStrs[int(v)]
  } else {
    return ""
  }
}

// Is the given severity valid for this CVSS version?
func (v Version) ValidSeverity(s Severity) bool {
  switch v {
  case V2:
    return s == Low || s == Medium || s == High
  case V30, V31:
    return s == Low || s == Medium || s == High || s == Critical
  default:
    return false
  }
}
