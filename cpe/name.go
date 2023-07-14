package cpe

import (
  "fmt"
  "strings"
)

// CPE name used as parameter in `CvesParams` structure.
type Name []string

// Number of leading components of CPE name which must be must not be
// "*".
const numRequiredNameComponents = 6

// create a new CPE name from the given string.
// Returns an error if the given string could not be converted to a CPE
// name.
func ParseName(s string) (*Name, error) {
  // split into components
  cs := strings.Split(s, ":")

  // check component count
  if len(cs) != 13 {
    return nil, fmt.Errorf("invalid component count: %d != 13", len(cs))
  }

  // check prefix
  if err := checkPrefix(cs); err != nil {
    return nil, err
  }

  // check required components
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
