package cpe

import (
  "fmt"
  "strings"
)

// CPE name used as parameter in `CvesParams` structure.
type Name []string

// Expected CPE name prefix components.
var expNamePrefix = []string { "cpe", "2.3" }

// Number of leading components of CPE name which must be must not be
// "*".
const numRequiredNameComponents = 6

// create a new CPE name from the given string.
// Returns an error if the given string could not be converted to a CPE
// name.
func ParseName(s string) (*Name, error) {
  // split into components
  cs := strings.Split(s, ":")

  // check component length
  if len(cs) != 13 {
    return nil, fmt.Errorf("invalid component count: %d != 13", len(cs))
  }
  // check for expected CPE name prefix components
  for i, exp := range(expNamePrefix) {
    if cs[i] != exp {
      return nil, fmt.Errorf("invalid CPE name component %d: %s != %s", i, cs[i], exp)
    }
  }

  // check for required CPE name components
  for i := 0; i < numRequiredNameComponents; i++ {
    if cs[i] == "*" {
      return nil, fmt.Errorf("CPE name component %d cannot be wildcard", i)
    }
  }

  // build result
  r := Name(cs[2:])

  // return result
  return &r, nil
}

// Parse string as CPE name or panic on error.
func MustParseName(s string) *Name {
  if n, err := ParseName(s); err == nil {
    return n
  } else {
    panic(err)
  }
}

// return Name as string
func (n Name) String() string {
  return "cpe:2.3:" + strings.Join([]string(n), ":")
}
