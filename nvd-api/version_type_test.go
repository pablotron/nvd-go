package nvd_api

import "testing"

func TestVersionTypeString(t *testing.T) {
  passTests := []struct {
    val VersionType // test value
    exp string // expected string value
  } {
    { DefaultVersionType, "" },
    { Including, "including" },
    { Excluding, "excluding" },
  }

  for _, test := range(passTests) {
    t.Run(test.exp, func(t *testing.T) {
      got := test.val.String()
      if got != test.exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, test.exp)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val VersionType // test value
  } {
    { "invalid", VersionType(255) },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      got := test.val.String()
      exp := "<invalid>"
      if got != exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
      }
    })
  }
}
