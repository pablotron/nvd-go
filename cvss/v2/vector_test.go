package v2

import (
  "pmdn.org/nvd-go/cvss"
  "reflect"
  "testing"
)

func TestKeyStrings(t *testing.T) {
  passTests := []struct {
    val Key // test value
    expId, expName string // expected id string and name string
  } {
    { AV, "AV", "Access Vector" },
    { AC, "AC", "Access Complexity" },
    { Au, "Au", "Authentication" },
    { C, "C", "Confidentiality Impact" },
    { I, "I", "Integrity Impact" },
    { A, "A", "Availability Impact" },
    { E, "E", "Exploitability" },
    { RL, "RL", "Remediation Level" },
    { RC, "RC", "Report Confidence" },
    { CDP, "CDP", "Collateral Damage Potential" },
    { TD, "TD", "Target Distribution" },
    { CR, "CR", "Confidentiality Requirement" },
    { IR, "IR", "Integrity Requirement" },
    { AR, "AR", "Availability Requirement" },
    { invalidKey, "", "" },
    { Key(lastKey), "", "" },
  }

  // run pass tests
  for _, test := range(passTests) {
    t.Run(test.expId, func(t *testing.T) {
      // check ID
      t.Run("id", func(t *testing.T) {
        exp := test.expId
        got := test.val.String()
        if got != exp {
          t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
        }
      })

      // check name
      t.Run("name", func(t *testing.T) {
        exp := test.expName
        got := test.val.Name()
        if got != exp {
          t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
        }
      })
    })
  }
}

func TestValueStrings(t *testing.T) {
  passTests := []struct {
    val Value // test value
    expId, expName string // expected id string and name string
  } {
    { AdjacentNetwork, "A", "AdjacentNetwork" },
    { Complete, "C", "Complete" },
    { Confirmed, "C", "Confirmed" },
    { Functional, "F", "Functional" },
    { High, "H", "High" },
    { Local, "L", "Local" },
    { Low, "L", "Low" },
    { LowMedium, "LM", "LowMedium" },
    { Medium, "M", "Medium" },
    { MediumHigh, "MH", "MediumHigh" },
    { Multiple, "M", "Multiple" },
    { Network, "N", "Network" },
    { None, "N", "None" },
    { NotDefined, "ND", "NotDefined" },
    { OfficialFix, "OF", "OfficialFix" },
    { Partial, "P", "Partial" },
    { ProofOfConcept, "POC", "ProofOfConcept" },
    { Single, "S", "Single" },
    { TemporaryFix, "TF", "TemporaryFix" },
    { Unavailable, "U", "Unavailable" },
    { Unconfirmed, "UC", "Unconfirmed" },
    { Uncorroborated, "UR", "Uncorroborated" },
    { Unproven, "U", "Unproven" },
    { Workaround, "W", "Workaround" },
    { lastValue, "", "" },
  }

  // run pass tests
  for _, test := range(passTests) {
    t.Run(test.expId, func(t *testing.T) {
      // check ID
      t.Run("id", func(t *testing.T) {
        exp := test.expId
        got := test.val.String()
        if got != exp {
          t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
        }
      })

      // check name
      t.Run("name", func(t *testing.T) {
        exp := test.expName
        got := test.val.Name()
        if got != exp {
          t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
        }
      })
    })
  }
}

func TestMetricStrings(t *testing.T) {
  passTests := []struct {
    val Metric // test metric
    expStr string // expected string value
    expKey Key // expected key
    expVal Value // expected value
  } {
    { AV_N, "AV:N", AV, Network },
    { AV_A, "AV:A", AV, AdjacentNetwork },
    { AV_L, "AV:L", AV, Local },
    { AC_H, "AC:H", AC, High },
    { AC_M, "AC:M", AC, Medium },
    { AC_L, "AC:L", AC, Low },
    { Au_M, "Au:M", Au, Multiple },
    { Au_S, "Au:S", Au, Single },
    { Au_N, "Au:N", Au, None },
    { C_N, "C:N", C, None },
    { C_P, "C:P", C, Partial },
    { C_C, "C:C", C, Complete },
    { I_N, "I:N", I, None },
    { I_P, "I:P", I, Partial },
    { I_C, "I:C", I, Complete },
    { A_N, "A:N", A, None },
    { A_P, "A:P", A, Partial },
    { A_C, "A:C", A, Complete },
    { E_U, "E:U", E, Unproven },
    { E_POC, "E:POC", E, ProofOfConcept },
    { E_F, "E:F", E, Functional },
    { E_H, "E:H", E, High },
    { E_ND, "E:ND", E, NotDefined },
    { RL_OF, "RL:OF", RL, OfficialFix },
    { RL_TF, "RL:TF", RL, TemporaryFix },
    { RL_W, "RL:W", RL, Workaround },
    { RL_U, "RL:U", RL, Unavailable },
    { RL_ND, "RL:ND", RL, NotDefined },
    { RC_UC, "RC:UC", RC, Unconfirmed },
    { RC_UR, "RC:UR", RC, Uncorroborated },
    { RC_C, "RC:C", RC, Confirmed },
    { RC_ND, "RC:ND", RC, NotDefined },
    { CDP_N, "CDP:N", CDP, None },
    { CDP_L, "CDP:L", CDP, Low },
    { CDP_LM, "CDP:LM", CDP, LowMedium },
    { CDP_MH, "CDP:MH", CDP, MediumHigh },
    { CDP_H, "CDP:H", CDP, High },
    { CDP_ND, "CDP:ND", CDP, NotDefined },
    { TD_N, "TD:N", TD, None },
    { TD_L, "TD:L", TD, Low },
    { TD_M, "TD:M", TD, Medium },
    { TD_H, "TD:H", TD, High },
    { TD_ND, "TD:ND", TD, NotDefined },
    { CR_L, "CR:L", CR, Low },
    { CR_M, "CR:M", CR, Medium },
    { CR_H, "CR:H", CR, High },
    { CR_ND, "CR:ND", CR, NotDefined },
    { IR_L, "IR:L", IR, Low },
    { IR_M, "IR:M", IR, Medium },
    { IR_H, "IR:H", IR, High },
    { IR_ND, "IR:ND", IR, NotDefined },
    { AR_L, "AR:L", AR, Low },
    { AR_M, "AR:M", AR, Medium },
    { AR_H, "AR:H", AR, High },
    { AR_ND, "AR:ND", AR, NotDefined },
    { invalidMetric, "", invalidKey, invalidValue },
    { lastMetric, "", invalidKey, invalidValue },
  }

  // run pass tests
  for _, test := range(passTests) {
    t.Run(test.expStr, func(t *testing.T) {
      // check string
      t.Run("string", func(t *testing.T) {
        exp := test.expStr
        got := test.val.String()
        if got != exp {
          t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
        }
      })

      // check key
      t.Run("key", func(t *testing.T) {
        exp := test.expKey
        got := test.val.Key()
        if got != exp {
          t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
        }
      })

      // check value
      t.Run("value", func(t *testing.T) {
        exp := test.expVal
        got := test.val.Value()
        if got != exp {
          t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
        }
      })
    })
  }
}

func TestParseVector(t *testing.T) {
  passTests := []struct {
    val string // test vector string
    exp []Metric // expected metrics
  } {
    // generated with testdata/get-vectors.rb
    { "AV:N/AC:L/Au:N/C:C/I:C/A:C", []Metric { AV_N, AC_L, Au_N, C_C, I_C, A_C } },
    { "AV:L/AC:L/Au:N/C:C/I:C/A:C", []Metric { AV_L, AC_L, Au_N, C_C, I_C, A_C } },
    { "AV:L/AC:L/Au:N/C:P/I:P/A:P", []Metric { AV_L, AC_L, Au_N, C_P, I_P, A_P } },
    { "AV:N/AC:L/Au:N/C:P/I:P/A:P", []Metric { AV_N, AC_L, Au_N, C_P, I_P, A_P } },
    { "AV:N/AC:L/Au:N/C:P/I:N/A:N", []Metric { AV_N, AC_L, Au_N, C_P, I_N, A_N } },
    { "AV:L/AC:L/Au:N/C:P/I:N/A:N", []Metric { AV_L, AC_L, Au_N, C_P, I_N, A_N } },
    { "AV:L/AC:H/Au:N/C:C/I:C/A:C", []Metric { AV_L, AC_H, Au_N, C_C, I_C, A_C } },
    { "AV:N/AC:L/Au:N/C:N/I:N/A:N", []Metric { AV_N, AC_L, Au_N, C_N, I_N, A_N } },
    { "AV:N/AC:L/Au:N/C:N/I:P/A:P", []Metric { AV_N, AC_L, Au_N, C_N, I_P, A_P } },
    { "AV:N/AC:M/Au:N/C:P/I:P/A:P", []Metric { AV_N, AC_M, Au_N, C_P, I_P, A_P } },
    { "AV:N/AC:L/Au:N/C:N/I:N/A:P", []Metric { AV_N, AC_L, Au_N, C_N, I_N, A_P } },
    { "AV:N/AC:H/Au:N/C:C/I:C/A:C", []Metric { AV_N, AC_H, Au_N, C_C, I_C, A_C } },
    { "AV:L/AC:H/Au:N/C:P/I:P/A:P", []Metric { AV_L, AC_H, Au_N, C_P, I_P, A_P } },
    { "AV:N/AC:L/Au:N/C:N/I:P/A:N", []Metric { AV_N, AC_L, Au_N, C_N, I_P, A_N } },
    { "AV:L/AC:M/Au:N/C:P/I:N/A:N", []Metric { AV_L, AC_M, Au_N, C_P, I_N, A_N } },
    { "AV:L/AC:L/Au:N/C:N/I:N/A:P", []Metric { AV_L, AC_L, Au_N, C_N, I_N, A_P } },
    { "AV:L/AC:L/Au:N/C:N/I:P/A:N", []Metric { AV_L, AC_L, Au_N, C_N, I_P, A_N } },
    { "AV:N/AC:L/Au:N/C:P/I:P/A:N", []Metric { AV_N, AC_L, Au_N, C_P, I_P, A_N } },
    // TODO
  }

  // run pass tests
  for _, test := range(passTests) {
    t.Run(test.val, func(t *testing.T) {
      // parse vector
      vec, err := ParseVector(test.val)
      if err != nil {
        t.Fatal(err)
      }

      // check string
      t.Run("string", func(t *testing.T) {
        exp := test.val
        got := vec.String()
        if got != exp {
          t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
        }
      })

      // check metrics
      t.Run("metrics", func(t *testing.T) {
        exp := test.exp
        got := vec.Metrics()
        if !reflect.DeepEqual(got, exp) {
          t.Fatalf("got \"%v\", exp \"%v\"", got, exp)
        }
      })
    })
  }

  failTests := []struct {
    name string // test name
    val string // test vector string
  } {{
    name: "empty",
  }, {
    name: "invalid prefix",
    val: "foo/AV:N",
  }, {
    name: "invalid metric",
    val: "foo:bar",
  }, {
    name: "duplicate metric",
    val: "AV:N/AV:A",
  }}

  // run fail tests
  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      // parse vector
      if vec, err := ParseVector(test.val); err == nil {
        t.Fatalf("got %v, exp err", vec)
      }
    })
  }
}

func TestMustParseVector(t *testing.T) {
  passTests := []string {
    // generated with testdata/get-vectors.rb
    "AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "AV:L/AC:L/Au:N/C:C/I:C/A:C",
    "AV:L/AC:L/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:P/I:N/A:N",
    "AV:L/AC:L/Au:N/C:P/I:N/A:N",
    "AV:L/AC:H/Au:N/C:C/I:C/A:C",
    "AV:N/AC:L/Au:N/C:N/I:N/A:N",
    "AV:N/AC:L/Au:N/C:N/I:P/A:P",
    "AV:N/AC:M/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:N/I:N/A:P",
    "AV:N/AC:H/Au:N/C:C/I:C/A:C",
    "AV:L/AC:H/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:N/I:P/A:N",
    "AV:L/AC:M/Au:N/C:P/I:N/A:N",
    "AV:L/AC:L/Au:N/C:N/I:N/A:P",
    "AV:L/AC:L/Au:N/C:N/I:P/A:N",
    "AV:N/AC:L/Au:N/C:P/I:P/A:N",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      defer func() {
        if err := recover(); err != nil {
          t.Fatal(err)
        }
      }()

      _ = MustParseVector(test)
    })
  }

  failTests := []struct {
    name string // test name
    val string // test vector string
  } {{
    name: "empty",
  }, {
    name: "invalid prefix",
    val: "foo/AV:N",
  }, {
    name: "invalid metric",
    val: "foo:bar",
  }, {
    name: "duplicate metric",
    val: "AV:N/AV:A",
  }}

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      defer func() {
        if recover() == nil {
          t.Fatal("got success, exp error")
        }
      }()

      _ = MustParseVector(test.val)
    })
  }
}

func TestVectorString(t *testing.T) {
  tests := []string {
    "AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "AV:L/AC:L/Au:N/C:C/I:C/A:C",
    "AV:L/AC:L/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:P/I:N/A:N",
    "AV:L/AC:L/Au:N/C:P/I:N/A:N",
    "AV:L/AC:H/Au:N/C:C/I:C/A:C",
    "AV:N/AC:L/Au:N/C:N/I:N/A:N",
    "AV:N/AC:L/Au:N/C:N/I:P/A:P",
    "AV:N/AC:M/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:N/I:N/A:P",
    "AV:N/AC:H/Au:N/C:C/I:C/A:C",
    "AV:L/AC:H/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:N/I:P/A:N",
    "AV:L/AC:M/Au:N/C:P/I:N/A:N",
    "AV:L/AC:L/Au:N/C:N/I:N/A:P",
    "AV:L/AC:L/Au:N/C:N/I:P/A:N",
    "AV:N/AC:L/Au:N/C:P/I:P/A:N",
  }

  for _, exp := range(tests) {
    t.Run(exp, func(t *testing.T) {
      // parse vector, get string
      got := MustParseVector(exp).String()
      if got != exp {
        t.Fatalf("got %s, exp %s", got, exp)
      }
    })
  }
}

func TestVectorVersion(t *testing.T) {
  var vec Vector
  got := vec.Version()
  exp := cvss.V2
  if got != exp {
    t.Fatalf("got %v, exp %v", got, exp)
  }
}

func TestValidVectorString(t *testing.T) {
  passTests := []string {
    "AV:N/AC:L/Au:N/C:C/I:C/A:C",
    "AV:L/AC:L/Au:N/C:C/I:C/A:C",
    "AV:L/AC:L/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:P/I:N/A:N",
    "AV:L/AC:L/Au:N/C:P/I:N/A:N",
    "AV:L/AC:H/Au:N/C:C/I:C/A:C",
    "AV:N/AC:L/Au:N/C:N/I:N/A:N",
    "AV:N/AC:L/Au:N/C:N/I:P/A:P",
    "AV:N/AC:M/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:N/I:N/A:P",
    "AV:N/AC:H/Au:N/C:C/I:C/A:C",
    "AV:L/AC:H/Au:N/C:P/I:P/A:P",
    "AV:N/AC:L/Au:N/C:N/I:P/A:N",
    "AV:L/AC:M/Au:N/C:P/I:N/A:N",
    "AV:L/AC:L/Au:N/C:N/I:N/A:P",
    "AV:L/AC:L/Au:N/C:N/I:P/A:N",
    "AV:N/AC:L/Au:N/C:P/I:P/A:N",
  }

  for _, test := range(passTests) {
    t.Run(test, func(t *testing.T) {
      got := ValidVectorString(test)
      exp := true
      if got != exp {
        t.Fatalf("got %t, exp %t", got, exp)
      }
    })
  }

  failTests := []struct {
    name string // test name
    val string // test vector string
  } {{
    name: "empty",
  }, {
    name: "invalid prefix",
    val: "foo/AV:N",
  }, {
    name: "invalid metric",
    val: "foo:bar",
  }}

  for _, test := range(failTests) {
    t.Run(test.name, func(t *testing.T) {
      got := ValidVectorString(test.val)
      exp := false
      if got != exp {
        t.Fatalf("got %t, exp %t", got, exp)
      }
    })
  }
}
