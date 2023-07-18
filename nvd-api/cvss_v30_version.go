package nvd_api

import "fmt"

// CVSS v3.0 version string.  Must be "3.0".
type CvssV30Version struct{}

// Unmarshal CVSS version 3.0 string from text.
func (v *CvssV30Version) UnmarshalText(text []byte) error {
  s := string(text)
  if s == "3.0" {
    return nil
  } else {
    return fmt.Errorf("invalid CVSS 3.0 version: \"%s\"", s)
  }
}

// Marshal CVSS V3.0 version string to text.
func (v *CvssV30Version) MarshalText() ([]byte, error) {
  return []byte("3.0"), nil
}

// Convert CVSS V3.0 version string to string.
func (v CvssV30Version) String() string {
  return "3.0"
}

