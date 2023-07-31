package nvd_api

import (
  "testing"
)

func TestFormatUnmarshalText(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp Format // expected format
  } {
    { "NVD_CVE", FormatCve },
    { "NVD_CVEHistory", FormatCveHistory },
    { "NVD_CPE", FormatCpe },
    { "NVD_CPEMatchString", FormatCpeMatch },
    { "NVD_SOURCE", FormatSource },
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
    { "Cve", FormatCve, "NVD_CVE" },
    { "CveHistory", FormatCveHistory, "NVD_CVEHistory" },
    { "Cpe", FormatCpe, "NVD_CPE" },
    { "CpeMatch", FormatCpeMatch, "NVD_CPEMatchString" },
    { "Source", FormatSource, "NVD_SOURCE" },
    { "UnknownFormat", FormatUnknown, "" },
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
