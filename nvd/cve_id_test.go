package nvd

import "testing"

func TestNewCveId(t *testing.T) {
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
  }}

  for _, test := range(passTests) {
    t.Run(test.name, func(t *testing.T) {
      id, err := NewCveId(test.val)
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
}
