package cve

import (
  "fmt"
  "testing"
)

func TestParseId(t *testing.T) {
  passTests := []struct {
    name string // test name
    val string // test value
    expString string // expected string
    expYear uint32 // expected year
    expNum uint32 // expected number
  } {{
    name: "basic",
    val: "CVE-2023-1234",
    expString: "CVE-2023-1234",
    expYear: 2023,
    expNum: 1234,
  }, {
    name: "octal",
    val: "CVE-2023-0013",
    expString: "CVE-2023-0013",
    expYear: 2023,
    expNum: 13,
  }, {
    name: "min year",
    val: "CVE-1900-1234",
    expString: "CVE-1900-1234",
    expYear: 1900,
    expNum: 1234,
  }, {
    name: "max year",
    val: "CVE-2155-1234",
    expString: "CVE-2155-1234",
    expYear: 2155,
    expNum: 1234,
  }, {
    name: "min num",
    val: "CVE-2023-0000",
    expString: "CVE-2023-0000",
    expYear: 2023,
    expNum: 0,
  }, {
    name: "max num",
    val: "CVE-2023-16777215",
    expString: "CVE-2023-16777215",
    expYear: 2023,
    expNum: 16777215,
  }}

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      id, err := ParseId(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // check year
      gotYear := id.Year()
      if gotYear != test.expYear {
        t.Fatalf("year mismatch: got %d, exp %d", gotYear, test.expYear)
      }

      // check number
      gotNum := id.Num()
      if gotNum != test.expNum {
        t.Fatalf("number mismatch: got %d, exp %d", gotNum, test.expNum)
      }

      // check string
      gotString := id.String()
      if gotString != test.expString {
        t.Fatalf("string mismatch: got %s, exp %s", gotString, test.expString)
      }
    })

    t.Run("nil", func(t *testing.T) {
      id := (*Id)(nil)

      t.Run("String", func(t *testing.T) {
        got := id.String()
        exp := ""
        if got != exp {
          t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
        }
      })

      t.Run("Year", func(t *testing.T) {
        got := id.Year()
        exp := uint32(0)
        if got != exp {
          t.Fatalf("got %d, exp %d", got, exp)
        }
      })

      t.Run("Num", func(t *testing.T) {
        got := id.Num()
        exp := uint32(0)
        if got != exp {
          t.Fatalf("got %d, exp %d", got, exp)
        }
      })
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {{
    name: "empty",
  }, {
    name: "garbage",
    val: "foo",
  }, {
    name: "invalid prefix",
    val: "abc-2023-05",
  }, {
    name: "wrong prefix case",
    val: "cve-2023-05",
  }, {
    name: "missing component",
    val: "CVE-2023-",
  }, {
    name: "low year",
    val: "CVE-1899-0000",
  }, {
    name: "high year",
    val: "CVE-2156-0000",
  }, {
    name: "high number",
    val: "CVE-2023-16777216",
  }}

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      if got, err := ParseId(test.val); err == nil {
        t.Fatalf("got %v, exp err", got)
      }
    })
  }
}

func TestMustParseId(t *testing.T) {
  passTests := []string {
    "CVE-2023-1234",
    "CVE-2023-0013",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      defer func() {
        if err := recover(); err != nil {
          t.Fatal(err)
        }
      }()

      // parse CVE ID
      _ = MustParseId(test)
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {{
    name: "empty",
  }, {
    name: "garbage",
    val: "foo",
  }}

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      defer func() {
        if recover() == nil {
          t.Fatal("got success, exp error")
        }
      }()

      // parse CVE ID
      _ = MustParseId(test.val)
    })
  }
}

func TestIdUnmarshalText(t *testing.T) {
  passTests := []string {
    "CVE-2023-1234",
    "CVE-2023-0013",
    "CVE-1900-1234",
    "CVE-2155-1234",
    "CVE-2023-0000",
    "CVE-2023-16777215",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      var id Id
      if err := id.UnmarshalText([]byte(test)); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {{
    name: "empty",
  }, {
    name: "garbage",
    val: "foo",
  }, {
    name: "invalid prefix",
    val: "abc-2023-05",
  }, {
    name: "wrong prefix case",
    val: "cve-2023-05",
  }, {
    name: "missing component",
    val: "CVE-2023-",
  }, {
    name: "low year",
    val: "CVE-1899-0000",
  }, {
    name: "high year",
    val: "CVE-2156-0000",
  }, {
    name: "high number",
    val: "CVE-2023-16777216",
  }}

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      var got Id
      if got.UnmarshalText([]byte(test.val)) == nil {
        t.Fatalf("got \"%s\", exp error", got.String())
      }
    })
  }
}

func TestIdMarshalJSON(t *testing.T) {
  passTests := []string {
    "CVE-2023-1234",
    "CVE-2023-0013",
    "CVE-1900-1234",
    "CVE-2155-1234",
    "CVE-2023-0000",
    "CVE-2023-16777215",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      id := MustParseId(test)
      gotBytes, err := id.MarshalJSON()
      if err != nil {
        t.Fatal(err)
      }

      exp := fmt.Sprintf("\"%s\"", test)
      got := string(gotBytes)
      if got != exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
      }
    })
  }
}
