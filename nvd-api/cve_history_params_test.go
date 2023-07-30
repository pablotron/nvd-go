package nvd_api

import (
  "pmdn.org/nvd-go/cve"
  "pmdn.org/nvd-go/rfc3339"
  "testing"
)

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

  // TODO: failTest: check missing checkStartDate, resultsPerPage=5001
}
