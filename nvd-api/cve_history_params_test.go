package nvd_api

import (
  "pablotron.org/nvd-go/cve"
  "pablotron.org/nvd-go/rfc3339"
  "testing"
)

func TestCveHistoryParamsCheck(t *testing.T) {
  passTests := []struct {
    name  string // test name
    val   CveHistoryParams // test value
  } {{
    name: "blank",
    val: CveHistoryParams {},
  }, {
    name: "cveId",
    val: CveHistoryParams {
      CveId: cve.MustParseId("CVE-2023-1234"),
    },
  }, {
    name: "changeEndDate and changeStartDate",
    val: CveHistoryParams {
      ChangeEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
      ChangeStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }, {
    name: "resultsPerPage",
    val: CveHistoryParams {
      ResultsPerPage: 1999,
    },
  }, {
    name: "startIndex",
    val: CveHistoryParams {
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
    val   CveHistoryParams // test value
  } {{
    name: "invalid resultsPerPage",
    val: CveHistoryParams {
      ResultsPerPage: 5001,
    },
  }, {
    name: "invalid date range",
    val: CveHistoryParams {
      ChangeEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
      ChangeStartDate: rfc3339.MustParseTime("2023-12-02T12:34:56Z"),
    },
  }, {
    name: "missing start date",
    val: CveHistoryParams {
      ChangeEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }, {
    name: "missing end date",
    val: CveHistoryParams {
      ChangeStartDate: rfc3339.MustParseTime("2023-12-02T12:34:56Z"),
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

func TestCveHistoryParamsQueryString(t *testing.T) {
  passTests := []struct {
    name  string // test name
    val   CveHistoryParams // test value
    exp   string // expected query string
  } {{
    name: "blank",
    val: CveHistoryParams {},
    exp: "",
  }, {
    name: "cveId",
    val: CveHistoryParams {
      CveId: cve.MustParseId("CVE-2023-1234"),
    },
    exp: "cveId=CVE-2023-1234",
  }, {
    name: "changeEndDate and changeStartDate",
    val: CveHistoryParams {
      ChangeEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
      ChangeStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
    exp: "changeEndDate=2023-12-01T12%3A34%3A56Z&changeStartDate=2023-12-01T12%3A34%3A56Z",
  }, {
    name: "resultsPerPage",
    val: CveHistoryParams {
      ResultsPerPage: 1999,
    },
    exp: "resultsPerPage=1999",
  }, {
    name: "startIndex",
    val: CveHistoryParams {
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
    val CveHistoryParams // test value
  } {
    { "invalid", CveHistoryParams { ResultsPerPage: 50000 } },
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
