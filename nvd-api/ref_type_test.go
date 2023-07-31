package nvd_api

import "testing"

func TestRefTypeUnmarshalText(t *testing.T) {
  passTests := []struct {
    val string // test value
    exp RefType // expected result
  } {
    { "Advisory", AdvisoryRefType },
    { "Change Log", ChangeLogRefType },
    { "Product", ProductRefType },
    { "Project", ProjectRefType },
    { "Vendor", VendorRefType },
    { "Version", VersionRefType },
  }

  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      var r RefType
      if err := r.UnmarshalText([]byte(test.val)); err != nil {
        t.Fatal(err)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test value
  } {
    { "empty", "" },
    { "unknown", "asdf" },
  }

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      var r RefType
      if err := r.UnmarshalText([]byte(test.val)); err == nil {
        t.Fatalf("got \"%s\", exp error", r)
      }
    })
  }
}

func TestRefTypeString(t *testing.T) {
  passTests := []struct {
    name string // test name
    val RefType // test value
    exp string // expected result
  } {
    { "AdvisoryRefType", AdvisoryRefType, "Advisory" },
    { "ChangeLogRefType", ChangeLogRefType, "Change Log" },
    { "ProductRefType", ProductRefType, "Product" },
    { "ProjectRefType", ProjectRefType, "Project" },
    { "VendorRefType", VendorRefType, "Vendor" },
    { "UnknownRefType", UnknownRefType, "" },
    { "RefType(255)", RefType(255), "" },
  }

  for _, test := range(passTests) {
    t.Run(test.exp, func(t *testing.T) {
      got := test.val.String()
      if got != test.exp {
        t.Fatalf("got \"%s\", exp \"%s\"", got, test.exp)
      }
    })
  }
}
