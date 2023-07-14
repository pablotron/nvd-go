package cvss

import "fmt"

// CVSS severity level.  Used to represent both CVSS V2 and CVSS V3
// severity levels.
type Severity byte

const (
  UnknownSeverity Severity = iota
  Low // Low severity
  Medium // Medium severity
  High // High severity
  Critical // Critical severity
)

// Parse string as CVSS severity.  Returns error if the given string is
// not a valid CVSS severity string.
func ParseSeverity(s string) (*Severity, error) {
  switch s {
  case "LOW":
    r := Low
    return &r, nil
  case "MEDIUM":
    r := Medium
    return &r, nil
  case "HIGH":
    r := High
    return &r, nil
  case "CRITICAL":
    r := Critical
    return &r, nil
  default:
    return nil, fmt.Errorf("invalid CVSS severity: \"%s\"", s)
  }
}

// Parse string as CVSS severity or panic if the given string is not not
// a valid CVSS severity string.
func MustParseSeverity(s string) *Severity {
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
