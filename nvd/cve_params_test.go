package nvd

import "testing"

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
      CpeName: MustParseCpeName("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*"),
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
      CveId: MustParseCveId("CVE-2023-1234"),
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
      CvssV2Severity: MustParseCvssSeverity("LOW"),
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
      CvssV3Severity: MustParseCvssSeverity("HIGH"),
    },
    exp: "cvssV3Severity=HIGH",
  }, {
    name: "cweId",
    val: CveParams {
      CweId: MustParseCweId("CWE-1"),
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
    name: "isVulnerable",
    val: CveParams {
      IsVulnerable: true,
    },
    exp: "isVulnerable=",
  }, {
    name: "keywordSearch",
    val: CveParams {
      KeywordSearch: "foo",
    },
    exp: "keywordSearch=foo",
  }, {
    name: "lastModStartDate",
    val: CveParams {
      LastModStartDate: MustParseTime("2023-12-01T12:34:56Z"),
    },
    exp: "lastModStartDate=2023-12-01T12%3A34%3A56Z",
  }, {
    name: "lastModEndDate",
    val: CveParams {
      LastModEndDate: MustParseTime("2023-12-01T12:34:56Z"),
    },
    exp: "lastModEndDate=2023-12-01T12%3A34%3A56Z",
  }, {
    name: "noRejected",
    val: CveParams {
      NoRejected: true,
    },
    exp: "noRejected=",
  }, {
    name: "pubStartDate",
    val: CveParams {
      PubStartDate: MustParseTime("2023-12-01T12:34:56Z"),
    },
    exp: "pubStartDate=2023-12-01T12%3A34%3A56Z",
  }, {
    name: "pubEndDate",
    val: CveParams {
      PubEndDate: MustParseTime("2023-12-01T12:34:56Z"),
    },
    exp: "pubEndDate=2023-12-01T12%3A34%3A56Z",
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
    name: "versionStart",
    val: CveParams {
      VersionStart: "1.2.3",
    },
    exp: "versionStart=1.2.3",
  }, {
    name: "versionStartType",
    val: CveParams {
      VersionStartType: Including,
    },
    exp: "versionStartType=including",
  }, {
    name: "versionEnd",
    val: CveParams {
      VersionEnd: "1.2.3",
    },
    exp: "versionEnd=1.2.3",
  }, {
    name: "versionEndType",
    val: CveParams {
      VersionEndType: Excluding,
    },
    exp: "versionEndType=excluding",
  }, {
    name: "virtualMatchString",
    val: CveParams {
      VirtualMatchString: "foo",
    },
    exp: "virtualMatchString=foo",
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
