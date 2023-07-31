package cvss

import (
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

// Map of strings to severities.  Used by `ParseSeverity()`.
var severityStrMap = map[string]Severity {
  "NONE": None,
  "LOW": Low,
  "MEDIUM": Medium,
  "HIGH": High,
  "CRITICAL": Critical,
}

// Parse string as CVSS severity.  Returns error if the given string is
// not a valid CVSS severity string.
func ParseSeverity(s string) (Severity, error) {
  if v, ok := severityStrMap[s]; ok {
    return v, nil
  } else {
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

// Severity to string.  Used by `String()`.
var severityStrs = [...]string {
  "",
  "NONE",
  "LOW",
  "MEDIUM",
  "HIGH",
  "CRITICAL",
}

// Convert CVSS severity to string.  Returns "" if the given CVSS
// severity is invalid.
func (s Severity) String() string {
  if int(s) < len(severityStrs) {
    return severityStrs[int(s)]
  } else {
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

// Marshal severity as text.
func (s Severity) MarshalText() ([]byte, error) {
  return []byte(s.String()), nil
}
