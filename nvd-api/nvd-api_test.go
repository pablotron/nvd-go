package nvd_api

import (
  "pmdn.org/nvd-go/rfc3339"
  "testing"
)

func TestCheckDateRange(t *testing.T) {
  passTests := []struct {
    name string // test name
    start, end *rfc3339.Time // start and end time
  } {
    { "empty", nil, nil },
    { "pair", rfc3339.MustParseTime("2023-01-02T12:34:56Z"), rfc3339.MustParseTime("2023-01-03T12:34:56Z") },
  }

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      if err := checkDateRange(test.name, test.start, test.end); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []struct {
    name string // test name
    start, end *rfc3339.Time // start and end time
  } {
    { "missing end", rfc3339.MustParseTime("2023-01-02T12:34:56Z"), nil },
    { "missing start", nil, rfc3339.MustParseTime("2023-01-02T12:34:56Z") },
    { "negative", rfc3339.MustParseTime("2023-01-03T12:34:56Z"), rfc3339.MustParseTime("2023-01-02T12:34:56Z") },
    { "max days", rfc3339.MustParseTime("2023-01-01T12:34:56Z"), rfc3339.MustParseTime("2023-06-01T12:34:56Z") },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      if checkDateRange(test.name, test.start, test.end) == nil {
        t.Fatal("got success, exp error")
      }
    })
  }
}
