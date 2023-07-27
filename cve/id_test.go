package cve

import "testing"

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
    val: "CVE-2023-0",
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
    val: "CVE-2023",
  }, {
    name: "low year",
    val: "CVE-1899-0",
  }, {
    name: "high year",
    val: "CVE-2156-0",
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
