package cve

import (
  "testing"
)

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
