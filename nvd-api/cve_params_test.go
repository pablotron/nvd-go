package nvd_api

import (
  "pablotron.org/nvd-go/cpe"
  "pablotron.org/nvd-go/cve"
  "pablotron.org/nvd-go/cvss"
  "pablotron.org/nvd-go/cwe"
  "pablotron.org/nvd-go/rfc3339"
  "testing"
)

func TestCveParamsCheck(t *testing.T) {
  failTests := []struct {
    name string // test name
    val CveParams // test value
  } {{
    name: "v2 metrics and v3 metrics combo",
    val: CveParams {
      CvssV2Metrics: "asdf",
      CvssV3Metrics: "asdf",
    },
  }, {
    name: "v2 severity and v3 severity combo",
    val: CveParams {
      CvssV2Severity: cvss.Low,
      CvssV3Severity: cvss.Low,
    },
  }, {
    name: "invalid v2 severity",
    val: CveParams {
      CvssV2Severity: cvss.Critical,
    },
  }, {
    name: "invalid v3 severity",
    val: CveParams {
      CvssV3Severity: cvss.Severity(255),
    },
  }, {
    name: "huge resultsPerPage",
    val: CveParams {
      ResultsPerPage: 50000,
    },
  }, {
    name: "isVulnerable w/o cpeName",
    val: CveParams {
      IsVulnerable: true,
    },
  }, {
    name: "isVulnerable and virtualMatchString",
    val: CveParams {
      IsVulnerable: true,
      CpeName: cpe.MustParseName("cpe:2.3:a:b:c:d:e:f:g:h:i:j:k"),
      VirtualMatchString: cpe.MustParseMatch("cpe:2.3:foo"),
    },
  }, {
    name: "keywordExactMatch w/o keywordSearch",
    val: CveParams {
      KeywordExactMatch: true,
    },
  }, {
    name: "lastModStartDate w/o lastModEndDate",
    val: CveParams {
      LastModStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }, {
    name: "pubStartDate w/o pubEndDate",
    val: CveParams {
      PubStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }, {
    name: "versionEnd w/o versionEndType",
    val: CveParams {
      VersionEnd: "asdf",
    },
  }, {
    name: "versionEndType w/o versionEnd",
    val: CveParams {
      VersionEndType: Including,
    },
  }, {
    name: "versionStart w/o versionStartType",
    val: CveParams {
      VersionStart: "asdf",
    },
  }, {
    name: "versionStartType w/o versionStart",
    val: CveParams {
      VersionStartType: Including,
    },
  }}

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      if test.val.Check() == nil {
        t.Fatal("got success, exp error")
      }
    })
  }
}

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
      CvssV2Severity: cvss.Low,
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
      CvssV3Severity: cvss.High,
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
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
      LastModStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
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
      PubEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
      PubStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
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

  failTests := []struct {
    name string // test name
    val CveParams // test value
  } {
    { "invalid", CveParams { ResultsPerPage: 50000 } },
  }

  // run fail tests
  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      // get query string
      if got, err := test.val.QueryString(); err == nil {
        t.Fatalf("got %s, exp error", got)
      }
    })
  }
}
