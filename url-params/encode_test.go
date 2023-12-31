package url_params

import (
  "testing"
)

// custom type that implements String().  Used to test Encode().
type Stringable struct {
  s string // string value
}

func (s Stringable) String() string { return s.s }

// Custom type that does not implement String().  Used to test Encode().
type NotStringable struct {
  s string // string value
}

// type which implements all url-taggable types.  Used to test Encode().
type Tagged struct {
  Bool bool `url:"bool"`
  Uint uint `url:"uint"`
  String string `url:"string"`
  Stringable Stringable `url:"stringable"`
  private string `url:"private"` // test private field
  Untagged string // test untagged field
}

// type which has a url-tagged field which has an unstringable type.
// Used by `TestEncode()`.
type BadTagged struct {
  NotStringable NotStringable `url:"notStringable"`
}

func TestEncode(t *testing.T) {
  passTests := []struct {
    name string // test name
    val *Tagged // test value
    exp string // expected string
  } {{
    name: "nil",
  }, {
    name: "empty",
    val: &Tagged {},
  }, {
    name: "bool-true",
    val: &Tagged { Bool: true },
    exp: "bool=",
  }, {
    name: "bool-false",
    val: &Tagged { Bool: false },
    exp: "",
  }, {
    name: "uint",
    val: &Tagged { Uint: 1234 },
    exp: "uint=1234",
  }, {
    name: "string",
    val: &Tagged { String: "hello there" },
    exp: "string=hello+there",
  }, {
    name: "stringable",
    val: &Tagged { Stringable: Stringable { "hi" } },
    exp: "stringable=hi",
  }, {
    name: "private",
    val: &Tagged { private: "asdf" },
    exp: "",
  }}

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      got, err := Encode(test.val)
      if err != nil {
        t.Fatal(err)
      }

      if got != test.exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, test.exp)
      }
    })
  }

  t.Run("fail", func(t *testing.T) {
    val := BadTagged { NotStringable { "asdf" } }
    if got, err := Encode(&val); err == nil {
      t.Fatalf("got \"%s\", exp error", got)
    }
  })
}
