package nvd_api

import "fmt"

// CVSS V2 version string.  Must be "2.0".
type CvssV2Version struct{}

// Unmarshal CVSS version 2.0 string from text.
func (v *CvssV2Version) UnmarshalText(text []byte) error {
  s := string(text)
  if s == "2.0" {
    return nil
  } else {
    return fmt.Errorf("invalid CVSS 2.0 version: \"%s\"", s)
  }
}

// Marshal CVSS V2 version string to text.
func (v *CvssV2Version) MarshalText() ([]byte, error) {
  return []byte("2.0"), nil
}

// Convert CVSS V2 version string to string.
func (v CvssV2Version) String() string {
  return "2.0"
}

