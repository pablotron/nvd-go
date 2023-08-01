package nvd_api

import (
  "github.com/google/uuid"
  "pmdn.org/nvd-go/cpe"
  "pmdn.org/nvd-go/rfc3339"
  "testing"
)

func TestCpeParamsCheck(t *testing.T) {
  passTests := []struct {
    name  string // test name
    val   CpeParams // test value
  } {{
    name: "blank",
    val: CpeParams {},
  }, {
    name: "cpeNameId",
    val: CpeParams {
      CpeNameId: uuid.MustParse("87316812-5F2C-4286-94FE-CC98B9EAEF53"),
    },
  }, {
    name: "cpeMatchString",
    val: CpeParams {
      CpeMatchString: cpe.MustParseMatch("cpe:2.3:o:microsoft:windows_10"),
    },
  }, {
    name: "keywordExactMatch AND keywordSearch",
    val: CpeParams {
      KeywordExactMatch: true,
      KeywordSearch: "foo",
    },
  }, {
    name: "lastModEndDate AND lastModStartDate",
    val: CpeParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-02T12:34:56Z"),
      LastModStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }, {
    name: "matchCriteriaId",
    val: CpeParams {
      MatchCriteriaId: uuid.MustParse("87316812-5F2C-4286-94FE-CC98B9EAEF53"),
    },
  }, {
    name: "resultsPerPage",
    val: CpeParams {
      ResultsPerPage: 1999,
    },
  }, {
    name: "startIndex",
    val: CpeParams {
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
    val   CpeParams // test value
  } {{
    name: "invalid resultsPerPage",
    val: CpeParams {
      ResultsPerPage: 10001,
    },
  }, {
    name: "invalid date range",
    val: CpeParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
      LastModStartDate: rfc3339.MustParseTime("2023-12-02T12:34:56Z"),
    },
  }, {
    name: "missing start date",
    val: CpeParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }, {
    name: "missing start date",
    val: CpeParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
  }, {
    name: "missing keywordSearch",
    val: CpeParams {
      KeywordExactMatch: true,
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

func TestCpeParamsQueryString(t *testing.T) {
  passTests := []struct {
    name  string // test name
    val   CpeParams // test value
    exp   string // expected query string
  } {{
    name: "blank",
    val: CpeParams {},
    exp: "",
  }, {
    name: "cpeNameId",
    val: CpeParams {
      CpeNameId: uuid.MustParse("87316812-5F2C-4286-94FE-CC98B9EAEF53"),
    },
    exp: "cpeNameId=87316812-5f2c-4286-94fe-cc98b9eaef53",
  }, {
    name: "cpeMatchString",
    val: CpeParams {
      CpeMatchString: cpe.MustParseMatch("cpe:2.3:foo"),
    },
    exp: "cpeMatchString=cpe%3A2.3%3Afoo",
  }, {
    name: "keywordSearch",
    val: CpeParams {
      KeywordSearch: "foo",
    },
    exp: "keywordSearch=foo",
  }, {
    name: "keywordExactMatch and keywordSearch",
    val: CpeParams {
      KeywordExactMatch: true,
      KeywordSearch: "foo",
    },
    exp: "keywordExactMatch=&keywordSearch=foo",
  }, {
    name: "lastModEndDate and lastModStartDate",
    val: CpeParams {
      LastModEndDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
      LastModStartDate: rfc3339.MustParseTime("2023-12-01T12:34:56Z"),
    },
    exp: "lastModEndDate=2023-12-01T12%3A34%3A56Z&lastModStartDate=2023-12-01T12%3A34%3A56Z",
  }, {
    name: "matchCriteriaId",
    val: CpeParams {
      MatchCriteriaId: uuid.MustParse("87316812-5F2C-4286-94FE-CC98B9EAEF53"),
    },
    exp: "matchCriteriaId=87316812-5f2c-4286-94fe-cc98b9eaef53",
  }, {
    name: "resultsPerPage",
    val: CpeParams {
      ResultsPerPage: 9999,
    },
    exp: "resultsPerPage=9999",
  }, {
    name: "startIndex",
    val: CpeParams {
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
    val CpeParams // test value
  } {
    { "invalid", CpeParams { ResultsPerPage: 50000 } },
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
