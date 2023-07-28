package cvss

import (
  "encoding/json"
  "fmt"
)

// CVSS severity level.  Used to represent both CVSS V2 and CVSS V3
// severity levels.
type Severity byte

const (
  Unknown Severity = iota
  None // None
  Low // Low severity
  Medium // Medium severity
  High // High severity
  Critical // Critical severity
)

// Parse string as CVSS severity.  Returns error if the given string is
// not a valid CVSS severity string.
func ParseSeverity(s string) (Severity, error) {
  switch s {
  case "LOW":
    return Low, nil
  case "MEDIUM":
    return Medium, nil
  case "HIGH":
    return High, nil
  case "CRITICAL":
    return Critical, nil
  default:
    return Unknown, fmt.Errorf("invalid CVSS severity: \"%s\"", s)
  }
}

// Parse string as CVSS severity or panic if the given string is not not
// a valid CVSS severity string.
func MustParseSeverity(s string) Severity {
  if severity, err := ParseSeverity(s); err == nil {
    return severity
  } else {
    panic(err)
  }
}

// Convert CVSS severity to string.  Returns "" if the given CVSS
// severity is invalid.
func (s Severity) String() string {
  switch s {
  case Low:
    return "LOW"
  case Medium:
    return "MEDIUM"
  case High:
    return "HIGH"
  case Critical:
    return "CRITICAL"
  default:
    return ""
  }
}

// Unmarshal severity from text.
func (s *Severity) UnmarshalText(b []byte) error {
  // parse severity
  ns, err := ParseSeverity(string(b))
  if err != nil {
    return err
  }

  // save result, return success
  *s = ns
  return nil
}

// Marshal severity as JSON string.
func (s Severity) MarshalJSON() ([]byte, error) {
  return json.Marshal(s.String())
}
