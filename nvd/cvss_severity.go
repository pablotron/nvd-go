package nvd

import "fmt"

// CVSS severity level.  Used to represent both CVSS V2 and CVSS V3
// severity levels.
type CvssSeverity byte

const (
  UnknownCvssSeverity CvssSeverity = iota
  LowSeverity // Low severity
  MediumSeverity // Medium severity
  HighSeverity // High severity
  CriticalSeverity // Critical severity
)

// Parse string as CVSS severity.  Returns error if the given string is
// not a valid CVSS severity string.
func ParseCvssSeverity(s string) (*CvssSeverity, error) {
  switch s {
  case "LOW":
    r := LowSeverity
    return &r, nil
  case "MEDIUM":
    r := MediumSeverity
    return &r, nil
  case "HIGH":
    r := HighSeverity
    return &r, nil
  case "CRITICAL":
    r := CriticalSeverity
    return &r, nil
  default:
    return nil, fmt.Errorf("invalid CVSS severity: \"%s\"", s)
  }
}

// Parse string as CVSS severity or panic if the given string is not not
// a valid CVSS severity string.
func MustParseCvssSeverity(s string) *CvssSeverity {
  if severity, err := ParseCvssSeverity(s); err == nil {
    return severity
  } else {
    panic(err)
  }
}

// Convert CVSS severity to string.  Returns "" if the given CVSS
// severity is invalid.
func (s CvssSeverity) String() string {
  switch s {
  case LowSeverity:
    return "LOW"
  case MediumSeverity:
    return "MEDIUM"
  case HighSeverity:
    return "HIGH"
  case CriticalSeverity:
    return "CRITICAL"
  default:
    return ""
  }
}

// Is the given severity a valid CVSS V2 severity?
func (s CvssSeverity) isValidV2Severity() bool {
  return s == LowSeverity || s == MediumSeverity || s == HighSeverity
}

// Is the given severity a valid CVSS V3 severity?
func (s CvssSeverity) isValidV3Severity() bool {
  return s == LowSeverity || s == MediumSeverity || s == HighSeverity || s == CriticalSeverity
}
