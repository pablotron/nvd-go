package nvd_api

import "testing"

func TestParseRefUrl(t *testing.T) {
  passTests := []string {
    "http://example.com/",
    "https://example.com/",
    "ftp://example.com/",
    "ftps://example.com/",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      if _, err := ParseRefUrl(test); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "invalid scheme", "foo://example.com/" },
    { "invalid host", "http://" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      if got, err := ParseRefUrl(test.val); err == nil {
        t.Fatalf("got %v, exp error", got)
      }
    })
  }
}

func TestMustParseRefUrl(t *testing.T) {
  passTests := []string {
    "http://example.com/",
    "https://example.com/",
    "ftp://example.com/",
    "ftps://example.com/",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      defer func() {
        if err := recover(); err != nil {
          t.Fatal(err)
        }
      }()

      // parse string
      _ = MustParseRefUrl(test)
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "invalid scheme", "foo://example.com/" },
    { "invalid host", "http://" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      defer func() {
        if recover() == nil {
          t.Fatal("got success, exp error")
        }
      }()

      // parse string
      _ = MustParseRefUrl(test.val)
    })
  }
}

func TestRefUrlString(t *testing.T) {
  passTests := []string {
    "http://example.com/",
    "https://example.com/",
    "ftp://example.com/",
    "ftps://example.com/",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      // parse url
      url, err := ParseRefUrl(test)
      if err != nil {
        t.Fatal(err)
      }

      got := url.String()
      exp := test
      if got != exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
      }
    })
  }
}


func TestRefUrlUnmarshalText(t *testing.T) {
  passTests := []string {
    "http://example.com/",
    "https://example.com/",
    "ftp://example.com/",
    "ftps://example.com/",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      var got RefUrl
      if err := got.UnmarshalText([]byte(test)); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "invalid scheme", "foo://example.com/" },
    { "invalid host", "http://" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      var got RefUrl
      if got.UnmarshalText([]byte(test.val)) == nil {
        t.Fatalf("got \"%s\", exp error", got)
      }
    })
  }
}
