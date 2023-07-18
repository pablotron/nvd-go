package nvd_api

import (
  "encoding/json"
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

func (r RefUrl) String() string {
  return string(r)
}

func (r *RefUrl) UnmarshalJSON(b []byte) error {
  // unmarshal string
  var s string
  if err := json.Unmarshal(b, &s); err != nil {
    return err
  }

  // parse string
  nr, err := ParseRefUrl(s)
  if err != nil {
    return err
  }

  // save result, return success
  *r = *nr
  return nil
}
