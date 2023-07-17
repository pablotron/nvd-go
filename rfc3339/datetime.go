package rfc3339

import (
  "encoding/json"
  "errors"
  "time"
)

// RFC3339 style date and time, without time zone specifier.
//
// Used by several timestamp field in NVD API responses, which vary from
// RFC3339 times because they have millisection precision but no
// timezone.
type DateTime time.Time

// Parse given string as DateTime or panic on error.
func MustParseDateTime(s string) *DateTime {
  if t, err := ParseDateTime(s); err != nil {
    panic(err)
  } else {
    return t
  }
}

// Parse layout for DateTime string.
const dateTimeLayout = `2006-01-02T15:04:05.999`

// Parse datetime st withtime zone from given string.  Returns
// error if the given string could not be parsed as a time.
func ParseDateTime(s string) (*DateTime, error) {
  if t, err := time.Parse(dateTimeLayout, s); err == nil {
    r := DateTime(t)
    return &r, nil
  } else {
    return nil, err
  }
}

// Error returned by `Time()` method when the given DateTime is nil.
var errNilDateTime = errors.New("nil datetime")

// Convert DateTime to time.Time object.  Returns an error if the given
// value is nil.
func (t *DateTime) Time() (*time.Time, error) {
  if t != nil {
    r := time.Time(*t)
    return &r, nil
  } else {
    return nil, errNilDateTime
  }
}

// Return time as a RFC3339-formatted string.  Returns an empty string
// if the given time value is nil.
func (t *DateTime) String() string {
  if t != nil {
    return time.Time(*t).Format(time.RFC3339)
  } else {
    return ""
  }
}

func (t *DateTime) UnmarshalJSON(b []byte) error {
  // unmarshal string
  var s string
  if err := json.Unmarshal(b, &s); err != nil {
    return err
  }

  // parse string as datetime
  nt, err := ParseDateTime(s)
  if err != nil {
    return err
  }

  *t = *nt
  return nil
}
