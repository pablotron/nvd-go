package nvd_api

import "fmt"

// NVD API v2.0 version string.
const versionStr = "2.0"

// NVD API v2.0 version string.  Must be "2.0".
type VersionString struct{}

// Unmarshal NVD API version string from text.
func (v *VersionString) UnmarshalText(b []byte) error {
  s := string(b)
  if s == versionStr {
    return nil
  } else {
    return fmt.Errorf("invalid NVD API  version: \"%s\"", s)
  }
}

// Marshal NVD API version string to text.
func (v *VersionString) MarshalText() ([]byte, error) {
  return []byte(versionStr), nil
}

// Convert NVD API version string to string.
func (v VersionString) String() string {
  return versionStr
}
