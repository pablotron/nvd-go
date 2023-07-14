package nvd

import (
  "reflect"
  "testing"
)

func TestNewCpeName(t *testing.T) {
  passTests := []struct {
    name string // test name
    val string // test value
    exp []string // expected CPE name components
  } {{
    name: "basic",
    val: "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",
    exp: []string { "o", "microsoft", "windows", "10", "*", "*", "*", "*", "*", "*", "*" },
  }}

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      // parse name
      cpeName, err := NewCpeName(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // cast to slice and compare against expected value
      got := []string(*cpeName)
      if !reflect.DeepEqual(got, test.exp) {
        t.Fatalf("got %v, exp %v", got, test.exp)
      }
    })
  }
}

func TestCpeNameString(t *testing.T) {
  passTests := []struct {
    name string // test name
    val string // test value
    exp string // expected string
  } {{
    name: "basic",
    val: "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",
    exp: "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",
  }}

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      // parse name
      cpeName, err := NewCpeName(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // compare string
      got := cpeName.String()
      if got != test.exp {
        t.Fatalf("got %s, exp %s", got, test.exp)
      }
    })
  }
}
