package nvd_api

import (
  "fmt"
  "regexp"
)

// URL for reference object.  Limited to 500 characters, must begin with
// "(ftp|http)s?://".
type RefUrl string

var refUrlRe = regexp.MustCompile(`^(ftp|http)s?://\S+$`)

// Parse RefUrl from string.
func ParseRefUrl(s string) (*RefUrl, error) {
  if !refUrlRe.MatchString(s) {
    return nil, fmt.Errorf("invalid reference URL string: \"%s\"", s)
  }

  r := RefUrl(s)
  return &r, nil
}

// Parse RefUrl from string or panic on error.
func MustParseRefUrl(s string) *RefUrl {
  if r, err := ParseRefUrl(s); err == nil {
    return r
  } else {
    panic(err)
  }
}

// Convert reference URL to string.
func (r RefUrl) String() string {
  return string(r)
}

// Unmarshal text as reference URL.
func (r *RefUrl) UnmarshalText(b []byte) error {
  // parse string
  if nr, err := ParseRefUrl(string(b)); err == nil {
    *r = *nr
    return nil
  } else {
    return err
  }
}
