package rfc3339

import (
  "testing"
  "time"
)

func TestParseDateTime(t *testing.T) {
  passTests := []struct {
    name string // test name
    val string // test value
    exp string // expected time
  } {{
    name: "utc",
    val: "2023-01-02T12:34:56.123",
    exp: "2023-01-02T12:34:56.123",
  }, {
    name: "positive tz",
    val: "2023-01-02T12:34:56.321",
    exp: "2023-01-02T12:34:56.321",
  }, {
    name: "positive tz",
    val: "2023-01-02T12:34:56.456",
    exp: "2023-01-02T12:34:56.456",
  }}

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      // parse time
      nvdTime, err := ParseDateTime(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // get parsed time
      got, err := nvdTime.Time()
      if err != nil {
        t.Fatal(err)
      }

      // parse expected time
      exp, err := time.Parse(`2006-01-02T15:04:05.999`, test.exp)
      if err != nil {
        t.Fatal(err)
      }

      if !got.Equal(exp) {
        t.Fatalf("time mismatch: got %v, exp %v", got, exp)
      }
    })
  }
}
