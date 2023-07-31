package cve

import (
  "testing"
)

func TestEventNameUnmarshalText(t *testing.T) {
  passTests := []struct {
    name string // test name
    val string // test value
    exp EventName // expected string
  } {
    { "InitialAnalysis", "Initial Analysis", InitialAnalysis },
    { "Reanalysis", "Reanalysis", Reanalysis },
    { "CveModified", "CVE Modified", CveModified },
    { "ModifiedAnalysis", "Modified Analysis", ModifiedAnalysis },
    { "CveTranslated", "CVE Translated", CveTranslated },
    { "VendorComment", "Vendor Comment", VendorComment },
    { "CveSourceUpdate", "CVE Source Update", CveSourceUpdate },
    { "CpeDeprecationRemap", "CPE Deprecation Remap", CpeDeprecationRemap },
    { "CweRemap", "CWE Remap", CweRemap },
    { "CveRejected", "CVE Rejected", CveRejected },
    { "CveUnrejected", "CVE Unrejected", CveUnrejected },
  }

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      var got EventName
      if err := got.UnmarshalText([]byte(test.val)); err != nil {
        t.Fatal(err)
      }

      if got != test.exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, test.exp)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "invalid", "asdf" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      var got EventName
      if err := got.UnmarshalText([]byte(test.val)); err == nil {
        t.Fatalf("got \"%s\", exp err", got)
      }
    })
  }
}

func TestEventNameString(t *testing.T) {
  tests := []struct {
    name string // test name
    val EventName // test value
    exp string // expected string
  } {
    { "None", None, "" },
    { "InitialAnalysis", InitialAnalysis, "Initial Analysis" },
    { "Reanalysis", Reanalysis, "Reanalysis" },
    { "CveModified", CveModified, "CVE Modified" },
    { "ModifiedAnalysis", ModifiedAnalysis, "Modified Analysis" },
    { "CveTranslated", CveTranslated, "CVE Translated" },
    { "VendorComment", VendorComment, "Vendor Comment" },
    { "CveSourceUpdate", CveSourceUpdate, "CVE Source Update" },
    { "CpeDeprecationRemap", CpeDeprecationRemap, "CPE Deprecation Remap" },
    { "CweRemap", CweRemap, "CWE Remap" },
    { "CveRejected", CveRejected, "CVE Rejected" },
    { "CveUnrejected", CveUnrejected, "CVE Unrejected" },
    { "invalid", EventName(255), "" },
  }

  for _, test := range(tests) {
    t.Run(test.name, func(t *testing.T) {
      got := test.val.String()
      if got != test.exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, test.exp)
      }
    })
  }
}
