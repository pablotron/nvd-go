package nvd_api

import (
  "pablotron.org/nvd-go/rfc3339"
  "testing"
)

func TestSourceParamsCheck(t *testing.T) {
  passTests := []struct {
    name  string // test name
    val   SourceParams // test value
  } {{
    name: "blank",
    val: SourceParams {},
  }, {
    name: "lastModEndDate AND lastModStartDate",
    val: SourceParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-02T12:34:56Z"),
      LastModStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }, {
    name: "sourceIdentifier",
    val: SourceParams {
      SourceIdentifier: "foo",
    },
  }, {
    name: "resultsPerPage",
    val: SourceParams {
      ResultsPerPage: 999,
    },
  }, {
    name: "startIndex",
    val: SourceParams {
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
    val   SourceParams // test value
  } {{
    name: "invalid resultsPerPage",
    val: SourceParams {
      ResultsPerPage: 5001,
    },
  }, {
    name: "invalid date range",
    val: SourceParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
      LastModStartDate: rfc3339.MustParseTime("2023-12-02T12:34:56Z"),
    },
  }, {
    name: "missing start date",
    val: SourceParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }, {
    name: "missing start date",
    val: SourceParams {
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

func TestSourceParamsQueryString(t *testing.T) {
  passTests := []struct {
    name  string // test name
    val   SourceParams // test value
    exp   string // expected query string
  } {{
    name: "blank",
    val: SourceParams {},
    exp: "",
  }, {
    name: "lastModEndDate and lastModStartDate",
    val: SourceParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
      LastModStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
    exp: "lastModEndDate=2023-12-01T12%3A34%3A56Z&lastModStartDate=2023-12-01T12%3A34%3A56Z",
  }, {
    name: "sourceIdentifier",
    val: SourceParams {
      SourceIdentifier: "foo",
    },
    exp: "sourceIdentifier=foo",
  }, {
    name: "resultsPerPage",
    val: SourceParams {
      ResultsPerPage: 999,
    },
    exp: "resultsPerPage=999",
  }, {
    name: "startIndex",
    val: SourceParams {
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
    val SourceParams // test value
  } {
    { "invalid", SourceParams { ResultsPerPage: 50000 } },
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
