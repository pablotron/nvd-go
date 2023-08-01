package cpe

import (
  "encoding/json"
  "fmt"
  "strings"
)

// CPE match string.
type Match []string

// Parse given string into CPE match.
//
// Returns an error if the given string could not be converted to a CPE
// match.
func ParseMatch(s string) (*Match, error) {
  // split into components
  cs := strings.Split(s, ":")

  // check component count
  if len(cs) < 3 || len(cs) > 13 {
    return nil, fmt.Errorf("invalid component count: %d", len(cs))
  }

  // check prefix
  if err := checkPrefix(cs); err != nil {
    return nil, err
  }

  // build result
  r := Match(cs[2:])

  // return result
  return &r, nil
}

// Parse string as Match or panic on error.
func MustParseMatch(s string) *Match {
  if n, err := ParseMatch(s); err == nil {
    return n
  } else {
    panic(err)
  }
}

// Does this CPE match string match a range of versions?
func (m Match) RangedVersion() bool {
  cs := []string(m)
  return len(cs) < 4 || cs[3] == "*"
}

// Return CPE match as string.
func (m Match) String() string {
  return "cpe:2.3:" + strings.Join([]string(m), ":")
}

// Unmarshal CPE match string from text.
func (m *Match) UnmarshalText(b []byte) error {
  if nm, err := ParseMatch(string(b)); err == nil {
    *m = *nm
    return nil
  } else {
    return err
  }
}

// Marshal CPE match string as JSON string.
func (m Match) MarshalJSON() ([]byte, error) {
  return json.Marshal(m.String())
}
