// Common Platform Enumeration.
package cpe

import (
  "errors"
  "fmt"
)

// Expected prefix components of CPE names and matches.
var expPrefix = []string { "cpe", "2.3" }

var errBadPrefix = errors.New("invalid CPE prefix")

// Check for valid prefix.  
func checkPrefix(cs []string) error {
  // check component length
  if len(cs) < 2 {
    return errBadPrefix
  }

  // check for expected prefix components
  for i, exp := range(expPrefix) {
    if cs[i] != exp {
      return fmt.Errorf("invalid CPE component: %s != %s", cs[i], exp)
    }
  }

  // return success
  return nil
}
