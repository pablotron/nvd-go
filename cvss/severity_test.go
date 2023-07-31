package cvss

import (
  "testing"
)

func TestParseSeverity(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp Severity // expected severity
  } {
    { "NONE", None },
    { "LOW", Low },
    { "MEDIUM", Medium },
    { "HIGH", High },
    { "CRITICAL", Critical },
  }

  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      got, err := ParseSeverity(test.val)
      if err != nil {
        t.Fatal(err)
      }

      if got != test.exp {
        t.Fatalf("got %v, exp %v", got, test.exp)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "unknown", "foobar" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      if got, err := ParseSeverity(test.val); err == nil {
        t.Fatalf("got %v, exp error", got)
      }
    })
  }
}

func TestSeverityString(t *testing.T) {
  passTests := []struct {
    name string // test name
    val Severity // test severity
    exp string // expected string
  } {
    { "None", None, "NONE" },
    { "Low", Low, "LOW" },
    { "Medium", Medium, "MEDIUM" },
    { "High", High, "HIGH" },
    { "Critical", Critical, "CRITICAL" },
    { "Unknown", Unknown, "" },
    { "Severity(255)", Severity(255), "" },
  }

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      got := test.val.String()
      if got != test.exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, test.exp)
      }
    })
  }
}
