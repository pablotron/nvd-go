package cwe

import (
  "fmt"
  "strconv"
)

// CWE identifier.
//
// CWE identifiers are stored internally as an unsigned, 32-bit integer.
type Id uint32

// Create new CWE identifier from string.  Returns error if the given
// string could not be parsed as a CWE identifier.
func ParseId(s string) (*Id, error) {
  // check string length
  if len(s) < 5 {
    return nil, fmt.Errorf("invalid CWE ID \"%s\": string too short", s)
  }

  // split CWE ID into prefix and number components
  prefixStr := s[0:4]
  numStr := s[4:]

  // check for "CWE-" prefix
  if prefixStr != "CWE-" {
    return nil, fmt.Errorf("invalid CWE ID \"%s\": missing \"CWE-\" prefix", s)
  }

  // parse numeric component
  num, err := strconv.ParseUint(numStr, 10, 32)
  if err != nil {
    return nil, fmt.Errorf("invalid CWE ID \"%s\": %w", s, err)
  }

  // check for non-zero numeric component
  if num == 0 {
    return nil, fmt.Errorf("invalid CWE ID \"%s\": number component is zero", s)
  }

  // encode result as u32
  r := Id(uint32(num))

  // return result
  return &r, nil
}

// Parse given string as CVE ID.  Panics if the given string could not
// be parsed as a CVE ID.
func MustParseId(s string) *Id {
  if id, err := ParseId(s); err == nil {
    return id
  } else {
    panic(err)
  }
}

// Return CWE ID as string.  Returns "" if the given CWE ID is nil.
func (id *Id) String() string {
  if id != nil {
    return fmt.Sprintf("CWE-%d", id.Uint())
  } else {
    return ""
  }
}

// Get number component of CWE ID as unsigned 32-bit integer.  Returns 0
// if the given CWE ID is nil.
func (id *Id) Uint() uint32 {
  if id != nil {
    return uint32(*id)
  } else {
    return 0
  }
}
