package cvss

import (
  "fmt"
  "testing"
)

func TestParseVersion(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp Version // expected version
  } {
    { "2.0", V2 },
    { "3.0", V30 },
    { "3.1", V31 },
  }

  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      got, err := ParseVersion(test.val)
      if err != nil {
        t.Fatal(err)
      }

      if *got != test.exp {
        t.Fatalf("got %v, exp %v", got, test.exp)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "garbage", "asdf" },
    { "not supported", "4.0" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      if got, err := ParseVersion(test.val); err == nil {
        t.Fatalf("got %v, exp error", got)
      }
    })
  }
}

func TestVersionString(t *testing.T) {
  passTests := []struct {
    name string // test name
    val Version // test version
    exp string // expected string
  } {
    { "V2", V2, "2.0" },
    { "V30", V30, "3.0" },
    { "V31", V31, "3.1" },
    { "UnknownVersion", UnknownVersion, "" },
    { "Version(255)", Version(255), "" },
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

func TestValidSeverity(t *testing.T) {
  tests := []struct {
    version Version
    severity Severity
    exp bool
  } {
    { V2, Unknown, false },
    { V2, Low, true },
    { V2, Medium, true },
    { V2, High, true },
    { V2, Critical, false },
    { V30, Unknown, false },
    { V30, Low, true },
    { V30, Medium, true },
    { V30, High, true },
    { V30, Critical, true },
    { V31, Unknown, false },
    { V31, Low, true },
    { V31, Medium, true },
    { V31, High, true },
    { V31, Critical, true },
    { UnknownVersion, Unknown, false },
    { UnknownVersion, Low, false },
    { UnknownVersion, Medium, false },
    { UnknownVersion, High, false },
    { UnknownVersion, Critical, false },
  }

  for _, test := range(tests) {
    name := fmt.Sprintf("%s/%s", test.version, test.severity)
    t.Run(name, func(t *testing.T) {
      got := test.version.ValidSeverity(test.severity)
      if got != test.exp {
        t.Fatalf("got %t, exp %t", got, test.exp)
      }
    })
  }
}

func TestVersionUnmarshalText(t *testing.T) {
  passTests := []string {
    "2.0",
    "3.0",
    "3.1",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      var version Version
      if err := version.UnmarshalText([]byte(test)); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []string {
    "asdf",
  }

  for _, test := range(failTests) {
    t.Run(test, func(t *testing.T) {
      var got Version
      if got.UnmarshalText([]byte(test)) == nil {
        t.Fatalf("got %v, exp error", got)
      }
    })
  }
}
