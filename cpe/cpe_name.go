package nvd

import (
  "fmt"
  "strings"
)

// CPE name used as parameter in `CvesParams` structure.
type CpeName []string

// Expected prefix components of CPE name.
var expectedCpeNamePrefix = []string { "cpe", "2.3" }

// Number of leading components of CPE name which must be must not be
// "*".
const numRequiredCpeNameComponents = 6

// create a new CPE name from the given string.
// Returns an error if the given string could not be converted to a CPE
// name.
func NewCpeName(s string) (*CpeName, error) {
  // split into components
  cs := strings.Split(s, ":")

  // check component length
  if len(cs) != 13 {
    return nil, fmt.Errorf("invalid component count: %d != 13", len(cs))
  }
  // check for expected CPE name prefix components
  for i, exp := range(expectedCpeNamePrefix) {
    if cs[i] != exp {
      return nil, fmt.Errorf("invalid CPE name component %d: %s != %s", i, cs[i], exp)
    }
  }

  // check for required CPE name components
  for i := 0; i < numRequiredCpeNameComponents; i++ {
    if cs[i] == "*" {
      return nil, fmt.Errorf("CPE name component %d cannot be wildcard", i)
    }
  }

  // build result
  r := CpeName(cs[2:])

  // return result
  return &r, nil
}

// Parse string as CpeName or panic on error.
func MustParseCpeName(s string) *CpeName {
  if n, err := NewCpeName(s); err == nil {
    return n
  } else {
    panic(err)
  }
}

// return CpeName as string
func (n CpeName) String() string {
  return "cpe:2.3:" + strings.Join([]string(n), ":")
}
