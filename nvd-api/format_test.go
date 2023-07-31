package nvd_api

import (
  "testing"
)

func TestFormatUnmarshalText(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp Format // expected format
  } {
    { "NVD_CVE", Cve },
    { "NVD_CVEHistory", CveHistory },
    { "NVD_CPE", Cpe },
    { "NVD_CPEMatchString", CpeMatch },
    { "NVD_SOURCE", Source },
  }

  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      var f Format
      if err := f.UnmarshalText([]byte(test.val)); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      var f Format
      if err := f.UnmarshalText([]byte(test.val)); err == nil {
        t.Fatalf("got \"%s\", exp error", f.String())
      }
    })
  }
}

func TestFormatString(t *testing.T) {
  passTests := []struct {
    name string // test name
    val Format // test value
    exp string // expected string
  } {
    { "Cve", Cve, "NVD_CVE" },
    { "CveHistory", CveHistory, "NVD_CVEHistory" },
    { "Cpe", Cpe, "NVD_CPE" },
    { "CpeMatch", CpeMatch, "NVD_CPEMatchString" },
    { "Source", Source, "NVD_SOURCE" },
    { "UnknownFormat", UnknownFormat, "" },
    { "Format(255)", Format(255), "" },
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
