package nvd_api

import (
  "testing"
)

func TestOperatorUnmarshalText(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp Operator // expected operator
  } {
    { "AND", And },
    { "OR", Or },
  }

  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      var got Operator
      if err := got.UnmarshalText([]byte(test.val)); err != nil {
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
    { "invalid", "foo" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      var got Operator
      if err := got.UnmarshalText([]byte(test.val)); err == nil {
        t.Fatalf("got %v, exp error", got)
      }
    })
  }
}

func TestOperatorMarshalText(t *testing.T) {
  passTests := []struct {
    name string // test name
    val Operator // test operator
    exp string // expected string
  } {
    { "And", And, "AND" },
    { "Or", Or, "OR" },
    { "InvalidOperator", InvalidOperator, "" },
    { "Operator(255)", Operator(255), "" },
  }

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      gotBytes, err := test.val.MarshalText()
      if err != nil {
        t.Fatal(err)
      }

      got := string(gotBytes)
      if got != test.exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, test.exp)
      }
    })
  }
}

func TestOperatorString(t *testing.T) {
  passTests := []struct {
    name string // test name
    val Operator // test operator
    exp string // expected string
  } {
    { "And", And, "AND" },
    { "Or", Or, "OR" },
    { "InvalidOperator", InvalidOperator, "" },
    { "Operator(255)", Operator(255), "" },
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
