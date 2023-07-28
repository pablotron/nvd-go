package v2

import "fmt"

// CVSS v2.0 version string.
const versionStr = "2.0"

// CVSS V2 version string.  Must be "2.0".
type VersionString struct{}

// Unmarshal CVSS version 2.0 string from text.
func (v *VersionString) UnmarshalText(text []byte) error {
  s := string(text)
  if s == versionStr {
    return nil
  } else {
    return fmt.Errorf("invalid CVSS 2.0 version string: \"%s\"", s)
  }
}

// Marshal CVSS V2 version string to text.
func (v *VersionString) MarshalText() ([]byte, error) {
  return []byte(versionStr), nil
}

// Convert CVSS V2 version string to string.
func (v VersionString) String() string {
  return versionStr
}

