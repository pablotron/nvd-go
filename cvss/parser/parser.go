// CVSS vector string parser.
package parser

import (
  "pmdn.org/nvd-go/cvss"
  "pmdn.org/nvd-go/cvss/v2"
  "pmdn.org/nvd-go/cvss/v30"
  "pmdn.org/nvd-go/cvss/v31"
)

// Parse vector string into v2.0, v3.0, or v3.1 CVSS vector.
func ParseVector(s string) (cvss.Vector, error) {
  if len(s) > 8 && s[0:9] == "CVSS:3.1/" {
    v, err := v31.ParseVector(s)
    return &v, err
  } else if len(s) > 8 && s[0:9] == "CVSS:3.0/" {
    v, err := v30.ParseVector(s)
    return &v, err
  } else {
    v, err := v2.ParseVector(s)
    return &v, err
  }
}

// Parse string into CVSS vector or panic on error.
func MustParseVector(s string) cvss.Vector {
  if v, err := ParseVector(s); err == nil {
    return v
  } else {
    panic(err)
  }
}
