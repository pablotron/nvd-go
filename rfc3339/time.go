package rfc3339

import (
  "encoding/json"
  "errors"
  "time"
)

// Time instance.
type Time time.Time

// Parse given string as Time or panic on error.
func MustParseTime(s string) *Time {
  if t, err := ParseTime(s); err != nil {
    panic(err)
  } else {
    return t
  }
}

// Parse RFC3339 timestamp with time zone from given string.  Returns
// error if the given string could not be parsed as a time.
func ParseTime(s string) (*Time, error) {
  if t, err := time.Parse(time.RFC3339, s); err == nil {
    r := Time(t)
    return &r, nil
  } else {
    return nil, err
  }
}

// Error returned by `Time()` when the given time value is nil.
var errNilTime = errors.New("nil time")

// Return time as a time.Time object.  Returns an error if the given
// time value is nil.
func (t *Time) Time() (*time.Time, error) {
  if t != nil {
    r := time.Time(*t)
    return &r, nil
  } else {
    return nil, errNilTime
  }
}

// Return time as a RFC3339-formatted string.  Returns an empty string
// if the given time value is nil.
func (t *Time) String() string {
  if t != nil {
    return time.Time(*t).Format(time.RFC3339)
  } else {
    return ""
  }
}

func (t *Time) UnmarshalJSON(b []byte) error {
  // unmarshal string
  var s string
  if err := json.Unmarshal(b, &s); err != nil {
    return err
  }

  // parse string
  nt, err := ParseTime(s)
  if err != nil {
    return err
  }

  *t = *nt
  return nil
}
