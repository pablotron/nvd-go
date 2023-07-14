package cpe

import "testing"

func TestCheckPrefix(t *testing.T) {
  passTests := []struct {
    name string // test name
    val []string // test value
  } {{
    name: "basic",
    val: []string { "cpe", "2.3" },
  }}

  // run pass tests
  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      if err := checkPrefix(test.val); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val []string // test value
  } {{
    name: "empty",
  }, {
    name: "short",
    val: []string { "foo" },
  }, {
    name: "bad cpe component",
    val: []string { "asdf", "2.3" },
  }, {
    name: "bad version component",
    val: []string { "cpe", "foo" },
  }}

  // run fail tests
  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      if err := checkPrefix(test.val); err == nil {
        t.Fatal("got success, exp err")
      }
    })
  }
}
