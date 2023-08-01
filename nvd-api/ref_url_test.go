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
