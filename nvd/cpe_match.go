package nvd

import (
  "fmt"
  "strings"
)

// CPE match string.
type CpeMatchString []string

// Expected prefix components of CPE match string.
var expectedCpeMatchStringPrefix = []string { "cpe", "2.3" }

// Parse given string into CPE match string.
//
// Returns an error if the given string could not be converted to a CPE
// match string.
func ParseCpeMatchString(s string) (*CpeMatchString, error) {
  // split into components
  cs := strings.Split(s, ":")

  // check component length
  if len(cs) < 3 {
    return nil, fmt.Errorf("invalid component count: %d < 3", len(cs))
  }
  // check for expected prefix components
  for i, exp := range(expectedCpeMatchStringPrefix) {
    if cs[i] != exp {
      return nil, fmt.Errorf("invalid CPE match string component %d: %s != %s", i, cs[i], exp)
    }
  }

  // build result
  r := CpeMatchString(cs[2:])

  // return result
  return &r, nil
}

// Parse string as CpeMatchString or panic on error.
func MustParseCpeMatchString(s string) *CpeMatchString {
  if n, err := ParseCpeMatchString(s); err == nil {
    return n
  } else {
    panic(err)
  }
}

// return CpeMatchString as string
func (ms CpeMatchString) String() string {
  return "cpe:2.3:" + strings.Join([]string(ms), ":")
}
