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

func TestMustParseSeverity(t *testing.T) {
  passTests := []string {
    "NONE",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      defer func() {
        if err := recover(); err != nil {
          t.Fatal(err)
        }
      }()

      _ = MustParseSeverity(test)
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
      defer func() {
        if recover() == nil {
          t.Fatal("got success, exp error")
        }
      }()

      _ = MustParseSeverity(test.val)
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

func TestSeverityUnmarshalText(t *testing.T) {
  passTests := []string {
    "NONE",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      var severity Severity
      if err := severity.UnmarshalText([]byte(test)); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []string {
    "asdf",
  }

  for _, test := range(failTests) {
    t.Run(test, func(t *testing.T) {
      var got Severity
      if err := got.UnmarshalText([]byte(test)); err == nil {
        t.Fatalf("got %v, exp error", got)
      }
    })
  }
}

func TestSeverityMarshalText(t *testing.T) {
  passTests := []struct {
    val Severity // test value
    exp string // expected string
  } {
    { None, "NONE" },
    { Low, "LOW" },
    { Medium, "MEDIUM" },
    { High, "HIGH" },
    { Critical, "CRITICAL" },
  }

  for _, test := range(passTests) {
    t.Run(test.exp, func(t *testing.T) {
      gotBytes, err := test.val.MarshalText()
      if err != nil {
        t.Fatal(err)
      }

      got := string(gotBytes)
      if got != test.exp {
        t.Fatalf("got %s, exp %s", got, test.exp)
      }
    })
  }
}
