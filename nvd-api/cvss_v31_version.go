package nvd_api

import "fmt"

// CVSS v3.1 version string.  Must be "3.1".
type CvssV31Version struct{}

// Unmarshal CVSS version 3.1 string from text.
func (v *CvssV31Version) UnmarshalText(text []byte) error {
  s := string(text)
  if s == "3.1" {
    return nil
  } else {
    return fmt.Errorf("invalid CVSS 3.1 version: \"%s\"", s)
  }
}

// Marshal CVSS V3.1 version string to text.
func (v *CvssV31Version) MarshalText() ([]byte, error) {
  return []byte("3.1"), nil
}

// Convert CVSS V3.1 version string to string.
func (v CvssV31Version) String() string {
  return "3.1"
}
