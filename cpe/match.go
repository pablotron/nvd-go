package cpe

import (
  "fmt"
  "strings"
)

// CPE match string.
type Match []string

// Expected prefix components of CPE match string.
var expMatchPrefix = []string { "cpe", "2.3" }

// Parse given string into CPE match.
//
// Returns an error if the given string could not be converted to a CPE
// match.
func ParseMatch(s string) (*Match, error) {
  // split into components
  cs := strings.Split(s, ":")

  // check component length
  if len(cs) < 3 {
    return nil, fmt.Errorf("invalid component count: %d < 3", len(cs))
  }
  // check for expected prefix components
  for i, exp := range(expMatchPrefix) {
    if cs[i] != exp {
      return nil, fmt.Errorf("invalid CPE match component %d: %s != %s", i, cs[i], exp)
    }
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
func (m Match) matchesVersionRange() bool {
  cs := []string(m)
  return len(cs) < 4 || cs[3] == "*"
}

// Return Match as string.
func (m Match) String() string {
  return "cpe:2.3:" + strings.Join([]string(m), ":")
}
