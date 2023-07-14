package nvd

import (
  "time"
)

type Time time.Time

func MustParseTime(s string) *Time {
  if t, err := NewTime(s); err != nil {
    panic(err)
  } else {
    return t
  }
}

func NewTime(s string) (*Time, error) {
  if t, err := time.Parse(time.RFC3339, s); err == nil {
    r := Time(t)
    return &r, nil
  } else {
    return nil, err
  }
}

func (t *Time) String() string {
  if t != nil {
    return time.Time(*t).Format(time.RFC3339)
  } else {
    return ""
  }
}
