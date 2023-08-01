package v31

import "testing"

func TestVersionString(t *testing.T) {
  exp := "3.1"

  t.Run("UnmarshalText", func(t *testing.T) {
    var got VersionString

    // test valid string
    if err := got.UnmarshalText([]byte(exp)); err != nil {
      t.Fatal(err)
    }

    // test invalid string
    if err := got.UnmarshalText([]byte("garbage")); err == nil {
      t.Fatalf("got %v, exp error", got)
    }
  })

  t.Run("MarshalText", func(t *testing.T) {
    var v VersionString

    gotBytes, err := v.MarshalText()
    if err != nil {
      t.Fatal(err)
    }

    got := string(gotBytes)
    if got != exp {
      t.Fatalf("got %s, exp %s", got, exp)
    }
  })

  t.Run("String", func(t *testing.T) {
    var v VersionString
    got := v.String()
    if got != exp {
      t.Fatalf("got %s, exp %s", got, exp)
    }
  })
}
