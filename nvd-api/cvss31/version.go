package cvss31

import "fmt"

const versionStr = "3.1"

// CVSS v3.1 version string.  Must be "3.1".
type Version struct{}

// Unmarshal CVSS version 3.1 string from text.
func (v *Version) UnmarshalText(text []byte) error {
  s := string(text)
  if s == versionStr {
    return nil
  } else {
    return fmt.Errorf("invalid CVSS 3.1 version: \"%s\"", s)
  }
}

// Marshal CVSS V3.1 version string to text.
func (v *Version) MarshalText() ([]byte, error) {
  return []byte(versionStr), nil
}

// Convert CVSS V3.1 version string to string.
func (v Version) String() string {
  return versionStr
}
