package cwe

import "testing"

func TestParseId(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp uint32 // expected numeric value
  } {{
    val: "CWE-1234",
    exp: 1234,
  }, {
    val: "CWE-1",
    exp: 1,
  }, {
    val: "CWE-12345678",
    exp: 12345678,
  }, {
    val: "CWE-4294967295", // (2**32)-1
    exp: 4294967295,
  }}

  // run pass tests
  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      // parse string
      id, err := ParseId(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // covert to uint32, then check it
      got := id.Uint()
      if got != test.exp {
        t.Fatalf("got %d, exp %d", got, test.exp)
      }
    })
  }

  // run fail tests
  failTests := []struct {
    name string // test name
    val string // test value
  } {{
    name: "empty",
    val: "",
  }, {
    name: "missing prefix",
    val: "1234",
  }, {
    name: "non-numeric",
    val: "CWE-asdf",
  }, {
    name: "out of range",
    val: "CWE-4294967296",
  }, {
    name: "zero",
    val: "CWE-0",
  }}

  // run fail tests
  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      // parse string, check for error
      if id, err := ParseId(test.val); err == nil {
        t.Fatalf("got %v, exp err", id)
      }
    })
  }
}
