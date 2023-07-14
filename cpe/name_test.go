package cpe

import (
  "reflect"
  "testing"
)

func TestParseName(t *testing.T) {
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
      name, err := ParseName(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // cast to slice and compare against expected value
      got := []string(*name)
      if !reflect.DeepEqual(got, test.exp) {
        t.Fatalf("got %v, exp %v", got, test.exp)
      }
    })
  }
}

func TestNameString(t *testing.T) {
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
      name, err := ParseName(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // compare string
      got := name.String()
      if got != test.exp {
        t.Fatalf("got %s, exp %s", got, test.exp)
      }
    })
  }
}
