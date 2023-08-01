package v30

import "fmt"

// CVSS v3.0 version string.
const versionStr = "3.0"

// CVSS v3.0 version string.  Must be "3.0".
type VersionString struct{}

// Unmarshal CVSS version 3.0 string from text.
func (v *VersionString) UnmarshalText(text []byte) error {
  s := string(text)
  if s == versionStr {
    return nil
  } else {
    return fmt.Errorf("invalid CVSS 3.0 version: \"%s\"", s)
  }
}

// Marshal CVSS V3.0 version string to text.
func (v *VersionString) MarshalText() ([]byte, error) {
  return []byte(versionStr), nil
}

// Convert CVSS V3.0 version string to string.
func (v VersionString) String() string {
  return versionStr
}
