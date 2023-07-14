package nvd_api

import (
  "pmdn.org/nvd-go/cpe"
  "pmdn.org/nvd-go/cve"
  "pmdn.org/nvd-go/cvss"
  "pmdn.org/nvd-go/cwe"
  "testing"
)

func TestCveParamsQueryString(t *testing.T) {
  passTests := []struct {
    name  string // test name
    val   CveParams // test value
    exp   string // expected query string
  } {{
    name: "blank",
    val: CveParams {},
    exp: "",
  }, {
    name: "cpeName",
    val: CveParams {
      CpeName: cpe.MustParseName("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*"),
    },
    exp: "cpeName=cpe%3A2.3%3Ao%3Amicrosoft%3Awindows%3A10%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A",
  }, {
    name: "test percent encoding",
    val: CveParams {
      KeywordSearch: "foo%",
    },
    exp: "keywordSearch=foo%25",
  }, {
    name: "multiple params",
    val: CveParams {
      KeywordSearch: "foo",
      CveId: cve.MustParseId("CVE-2023-1234"),
    },
    exp: "cveId=CVE-2023-1234&keywordSearch=foo",
  }, {
    name: "cvssV2Metrics",
    val: CveParams {
      CvssV2Metrics: "foo",
    },
    exp: "cvssV2Metrics=foo",
  }, {
    name: "cvssV2Severity",
    val: CveParams {
      CvssV2Severity: cvss.MustParseSeverity("LOW"),
    },
    exp: "cvssV2Severity=LOW",
  }, {
    name: "cvssV3Metrics",
    val: CveParams {
      CvssV3Metrics: "foo",
    },
    exp: "cvssV3Metrics=foo",
  }, {
    name: "cvssV3Severity",
    val: CveParams {
      CvssV3Severity: cvss.MustParseSeverity("HIGH"),
    },
    exp: "cvssV3Severity=HIGH",
  }, {
    name: "cweId",
    val: CveParams {
      CweId: cwe.MustParseId("CWE-1"),
    },
    exp: "cweId=CWE-1",
  }, {
    name: "hasCertAlerts",
    val: CveParams {
      HasCertAlerts: true,
    },
    exp: "hasCertAlerts=",
  }, {
    name: "hasCertNotes",
    val: CveParams {
      HasCertNotes: true,
    },
    exp: "hasCertNotes=",
  }, {
    name: "hasCertAlerts and hasCertNotes",
    val: CveParams {
      HasCertAlerts: true,
      HasCertNotes: true,
    },
    exp: "hasCertAlerts=&hasCertNotes=",
  }, {
    name: "hasKev",
    val: CveParams {
      HasKev: true,
    },
    exp: "hasKev=",
  }, {
    name: "hasOval",
    val: CveParams {
      HasOval: true,
    },
    exp: "hasOval=",
  }, {
    name: "isVulnerable and cpeName",
    val: CveParams {
      CpeName: cpe.MustParseName("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*"),
      IsVulnerable: true,
    },
    exp: "cpeName=cpe%3A2.3%3Ao%3Amicrosoft%3Awindows%3A10%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A&isVulnerable=",
  }, {
    name: "keywordSearch",
    val: CveParams {
      KeywordSearch: "foo",
    },
    exp: "keywordSearch=foo",
  }, {
    name: "lastModEndDate and lastModStartDate",
    val: CveParams {
      LastModEndDate: MustParseTime("2023-12-01T12:34:56Z"),
      LastModStartDate: MustParseTime("2023-12-01T12:34:56Z"),
    },
    exp: "lastModEndDate=2023-12-01T12%3A34%3A56Z&lastModStartDate=2023-12-01T12%3A34%3A56Z",
  }, {
    name: "noRejected",
    val: CveParams {
      NoRejected: true,
    },
    exp: "noRejected=",
  }, {
    name: "pubEndDate and pubStartDate",
    val: CveParams {
      PubEndDate: MustParseTime("2023-12-01T12:34:56Z"),
      PubStartDate: MustParseTime("2023-12-01T12:34:56Z"),
    },
    exp: "pubEndDate=2023-12-01T12%3A34%3A56Z&pubStartDate=2023-12-01T12%3A34%3A56Z",
  }, {
    name: "resultsPerPage",
    val: CveParams {
      ResultsPerPage: 1999,
    },
    exp: "resultsPerPage=1999",
  }, {
    name: "startIndex",
    val: CveParams {
      StartIndex: 31415,
    },
    exp: "startIndex=31415",
  }, {
    name: "sourceIdentifier",
    val: CveParams {
      SourceIdentifier: "foo",
    },
    exp: "sourceIdentifier=foo",
  }, {
    name: "versionStart and versionStartType",
    val: CveParams {
      VersionStart: "1.2.3",
      VersionStartType: Including,
    },
    exp: "versionStart=1.2.3&versionStartType=including",
  }, {
    name: "versionEnd and versionEndType",
    val: CveParams {
      VersionEnd: "1.2.3",
      VersionEndType: Excluding,
    },
    exp: "versionEnd=1.2.3&versionEndType=excluding",
  }, {
    name: "virtualMatchString",
    val: CveParams {
      VirtualMatchString: cpe.MustParseMatch("cpe:2.3:foo"),
    },
    exp: "virtualMatchString=cpe%3A2.3%3Afoo",
  }}

  // run pass tests
  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      // get query string
      got, err := test.val.QueryString()
      if err != nil {
        t.Fatal(err)
      }

      // check for expected value
      if got != test.exp {
        t.Fatalf("got %s, exp %s", got, test.exp)
      }
    })
  }
}
