package nvd_api

import (
  "github.com/google/uuid"
  "pablotron.org/nvd-go/cpe"
  "pablotron.org/nvd-go/cve"
  "pablotron.org/nvd-go/rfc3339"
  "testing"
)

func TestCpeMatchParamsCheck(t *testing.T) {
  passTests := []struct {
    name  string // test name
    val   CpeMatchParams // test value
  } {{
    name: "blank",
    val: CpeMatchParams {},
  }, {
    name: "cveId",
    val: CpeMatchParams {
      CveId: cve.MustParseId("CVE-2020-1234"),
    },
  }, {
    name: "lastModEndDate AND lastModStartDate",
    val: CpeMatchParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-02T12:34:56Z"),
      LastModStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }, {
    name: "matchCriteriaId",
    val: CpeMatchParams {
      MatchCriteriaId: uuid.MustParse("87316812-5F2C-4286-94FE-CC98B9EAEF53"),
    },
  }, {
    name: "matchStringSearch",
    val: CpeMatchParams {
      MatchStringSearch: cpe.MustParseMatch("cpe:2.3:*:cisco:adaptive_security_appliance:*"),
    },
  }, {
    name: "resultsPerPage",
    val: CpeMatchParams {
      ResultsPerPage: 1999,
    },
  }, {
    name: "startIndex",
    val: CpeMatchParams {
      StartIndex: 31415,
    },
  }}

  // run pass tests
  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      // check parameters
      if err := test.val.Check(); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []struct {
    name  string // test name
    val   CpeMatchParams // test value
  } {{
    name: "invalid resultsPerPage",
    val: CpeMatchParams {
      ResultsPerPage: 5001,
    },
  }, {
    name: "invalid date range",
    val: CpeMatchParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
      LastModStartDate: rfc3339.MustParseTime("2023-12-02T12:34:56Z"),
    },
  }, {
    name: "missing start date",
    val: CpeMatchParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }, {
    name: "missing start date",
    val: CpeMatchParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }}

  // run fail tests
  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      if err := test.val.Check(); err == nil {
        t.Fatalf("got success, exp err")
      }
    })
  }
}

func TestCpeMatchParamsQueryString(t *testing.T) {
  passTests := []struct {
    name  string // test name
    val   CpeMatchParams // test value
    exp   string // expected query string
  } {{
    name: "blank",
    val: CpeMatchParams {},
    exp: "",
  }, {
    name: "cveId",
    val: CpeMatchParams {
      CveId: cve.MustParseId("CVE-2023-1234"),
    },
    exp: "cveId=CVE-2023-1234",
  }, {
    name: "lastModEndDate and lastModStartDate",
    val: CpeMatchParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
      LastModStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
    exp: "lastModEndDate=2023-12-01T12%3A34%3A56Z&lastModStartDate=2023-12-01T12%3A34%3A56Z",
  }, {
    name: "matchCriteriaId",
    val: CpeMatchParams {
      MatchCriteriaId: uuid.MustParse("87316812-5F2C-4286-94FE-CC98B9EAEF53"),
    },
    exp: "matchCriteriaId=87316812-5f2c-4286-94fe-cc98b9eaef53",
  }, {
    name: "matchStringSearch",
    val: CpeMatchParams {
      MatchStringSearch: cpe.MustParseMatch("cpe:2.3:*:cisco:adaptive_security_appliance:*"),
    },
    exp: "matchStringSearch=cpe%3A2.3%3A%2A%3Acisco%3Aadaptive_security_appliance%3A%2A",
  }, {
    name: "resultsPerPage",
    val: CpeMatchParams {
      ResultsPerPage: 4999,
    },
    exp: "resultsPerPage=4999",
  }, {
    name: "startIndex",
    val: CpeMatchParams {
      StartIndex: 31415,
    },
    exp: "startIndex=31415",
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
    val CpeMatchParams // test value
  } {
    { "invalid", CpeMatchParams { ResultsPerPage: 5001 } },
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
