package cvss

import (
  "fmt"
  "testing"
)

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
