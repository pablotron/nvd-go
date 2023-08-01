package nvd_api

import "testing"

func TestVersionStringUnmarshalText(t *testing.T) {
  t.Run("pass", func(t *testing.T) {
    var v VersionString
    if err := v.UnmarshalText([]byte("2.0")); err != nil {
      t.Fatal(err)
    }
  })

  t.Run("fail", func(t *testing.T) {
    var v VersionString
    if err := v.UnmarshalText([]byte("asdf")); err == nil {
      t.Fatalf("got \"%s\", exp err", v)
    }
  })
}

func TestVersionStringMarshalText(t *testing.T) {
  var v VersionString

  gotBytes, err := v.MarshalText()
  if err != nil {
    t.Fatal(err)
  }

  got := string(gotBytes)
  exp := "2.0"
  if got != exp {
    t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
  }
}

func TestVersionStringString(t *testing.T) {
  var v VersionString

  got := v.String()
  exp := "2.0"
  if got != exp {
    t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
  }
}
