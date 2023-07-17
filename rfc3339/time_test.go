package rfc3339

import (
  "testing"
  "time"
)

func TestParseTime(t *testing.T) {
  passTests := []struct {
    name string // test name
    val string // test value
    exp string // expected time
  } {{
    name: "utc",
    val: "2023-01-02T12:34:56Z",
    exp: "2023-01-02T12:34:56Z",
  }, {
    name: "positive tz",
    val: "2023-01-02T12:34:56+01:00",
    exp: "2023-01-02T12:34:56+01:00",
  }, {
    name: "positive tz",
    val: "2023-01-02T12:34:56-01:00",
    exp: "2023-01-02T12:34:56-01:00",
  }}

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      // parse time
      nvdTime, err := ParseTime(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // get parsed time
      got, err := nvdTime.Time()
      if err != nil {
        t.Fatal(err)
      }

      // parse expected time
      exp, err := time.Parse(time.RFC3339, test.exp)
      if err != nil {
        t.Fatal(err)
      }

      if !got.Equal(exp) {
        t.Fatalf("time mismatch: got %v, exp %v", got, exp)
      }
    })
  }
}
