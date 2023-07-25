package v31

import (
  "reflect"
  "testing"
)

func TestKeyStrings(t *testing.T) {
  passTests := []struct {
    val Key // test value
    expId, expName string // expected id string and name string
  } {
    { AV, "AV", "Attack Vector" },
    { AC, "AC", "Attack Complexity" },
    { PR, "PR", "Privileges Required" },
    { UI, "UI", "User Interaction" },
    { S, "S", "Scope" },
    { C, "C", "Confidentiality Impact" },
    { I, "I", "Integrity Impact" },
    { A, "A", "Availability Impact" },
    { E, "E", "Exploit Code Maturity" },
    { RL, "RL", "Remediation Level" },
    { RC, "RC", "Report Confidence" },
    { CR, "CR", "Confidentiality Requirement" },
    { IR, "IR", "Integrity Requirement" },
    { AR, "AR", "Availability Requirement" },
    { MAV, "MAV", "Modified Attack Vector" },
    { MAC, "MAC", "Modified Attack Complexity" },
    { MPR, "MPR", "Modified Privileges Required" },
    { MUI, "MUI", "Modified User Interaction" },
    { MS, "MS", "Modified Scope" },
    { MC, "MC", "Modified Confidentiality Impact" },
    { MI, "MI", "Modified Integrity Impact" },
    { MA, "MA", "Modified Availability Impact" },
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
    { Changed, "C", "Changed" },
    { Confirmed, "C", "Confirmed" },
    { Functional, "F", "Functional" },
    { High, "H", "High" },
    { Local, "L", "Local" },
    { Low, "L", "Low" },
    { Medium, "M", "Medium" },
    { Network, "N", "Network" },
    { None, "N", "None" },
    { NotDefined, "X", "NotDefined" },
    { OfficialFix, "O", "OfficialFix" },
    { Physical, "P", "Physical" },
    { ProofOfConcept, "P", "ProofOfConcept" },
    { Reasonable, "R", "Reasonable" },
    { Required, "R", "Required" },
    { TemporaryFix, "T", "TemporaryFix" },
    { Unavailable, "U", "Unavailable" },
    { Unchanged, "U", "Unchanged" },
    { Unknown, "U", "Unknown" },
    { Unproven, "U", "Unproven" },
    { Workaround, "W", "Workaround" },
    { invalidValue, "", "" },
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

func TestElementStrings(t *testing.T) {
  passTests := []struct {
    val Element // test element
    expStr string // expected string value
    expKey Key // expected key
    expVal Value // expected value
  } {
    { AV_N, "AV:N", AV, Network },
    { AV_A, "AV:A", AV, AdjacentNetwork },
    { AV_L, "AV:L", AV, Local },
    { AV_P, "AV:P", AV, Physical },
    { AC_H, "AC:H", AC, High },
    { AC_L, "AC:L", AC, Low },
    { PR_H, "PR:H", PR, High },
    { PR_L, "PR:L", PR, Low },
    { PR_N, "PR:N", PR, None },
    { UI_N, "UI:N", UI, None },
    { UI_R, "UI:R", UI, Required },
    { S_U, "S:U", S, Unchanged },
    { S_C, "S:C", S, Changed },
    { C_N, "C:N", C, None },
    { C_L, "C:L", C, Low },
    { C_H, "C:H", C, High },
    { I_N, "I:N", I, None },
    { I_L, "I:L", I, Low },
    { I_H, "I:H", I, High },
    { A_N, "A:N", A, None },
    { A_L, "A:L", A, Low },
    { A_H, "A:H", A, High },
    { E_U, "E:U", E, Unproven },
    { E_P, "E:P", E, ProofOfConcept },
    { E_F, "E:F", E, Functional },
    { E_H, "E:H", E, High },
    { E_X, "E:X", E, NotDefined },
    { RL_O, "RL:O", RL, OfficialFix },
    { RL_T, "RL:T", RL, TemporaryFix },
    { RL_W, "RL:W", RL, Workaround },
    { RL_U, "RL:U", RL, Unavailable },
    { RL_X, "RL:X", RL, NotDefined },
    { RC_U, "RC:U", RC, Unknown },
    { RC_R, "RC:R", RC, Reasonable },
    { RC_C, "RC:C", RC, Confirmed },
    { RC_X, "RC:X", RC, NotDefined },
    { CR_L, "CR:L", CR, Low },
    { CR_M, "CR:M", CR, Medium },
    { CR_H, "CR:H", CR, High },
    { CR_X, "CR:X", CR, NotDefined },
    { IR_L, "IR:L", IR, Low },
    { IR_M, "IR:M", IR, Medium },
    { IR_H, "IR:H", IR, High },
    { IR_X, "IR:X", IR, NotDefined },
    { AR_L, "AR:L", AR, Low },
    { AR_M, "AR:M", AR, Medium },
    { AR_H, "AR:H", AR, High },
    { AR_X, "AR:X", AR, NotDefined },
    { MAV_N, "MAV:N", MAV, Network },
    { MAV_A, "MAV:A", MAV, AdjacentNetwork },
    { MAV_L, "MAV:L", MAV, Local },
    { MAV_P, "MAV:P", MAV, Physical },
    { MAV_X, "MAV:X", MAV, NotDefined },
    { MAC_H, "MAC:H", MAC, High },
    { MAC_L, "MAC:L", MAC, Low },
    { MAC_X, "MAC:X", MAC, NotDefined },
    { MPR_H, "MPR:H", MPR, High },
    { MPR_L, "MPR:L", MPR, Low },
    { MPR_N, "MPR:N", MPR, None },
    { MPR_X, "MPR:X", MPR, NotDefined },
    { MUI_N, "MUI:N", MUI, None },
    { MUI_R, "MUI:R", MUI, Required },
    { MUI_X, "MUI:X", MUI, NotDefined },
    { MS_U, "MS:U", MS, Unchanged },
    { MS_C, "MS:C", MS, Changed },
    { MS_X, "MS:X", MS, NotDefined },
    { MC_U, "MC:U", MC, Unchanged },
    { MC_C, "MC:C", MC, Changed },
    { MC_N, "MC:N", MC, None },
    { MC_L, "MC:L", MC, Low },
    { MC_H, "MC:H", MC, High },
    { MC_X, "MC:X", MC, NotDefined },
    { MI_U, "MI:U", MI, Unchanged },
    { MI_C, "MI:C", MI, Changed },
    { MI_N, "MI:N", MI, None },
    { MI_L, "MI:L", MI, Low },
    { MI_H, "MI:H", MI, High },
    { MI_X, "MI:X", MI, NotDefined },
    { MA_U, "MA:U", MA, Unchanged },
    { MA_C, "MA:C", MA, Changed },
    { MA_N, "MA:N", MA, None },
    { MA_L, "MA:L", MA, Low },
    { MA_H, "MA:H", MA, High },
    { MA_X, "MA:X", MA, NotDefined },
    { invalidElement, "", invalidKey, invalidValue },
    { lastElement, "", invalidKey, invalidValue },
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
    expStr string // expected vector string
    expEls []Element // expected elements
  } {
    { "CVSS:3.1/AV:N", "CVSS:3.1/AV:N", []Element { AV_N } },
    { "CVSS:3.1/AV:A", "CVSS:3.1/AV:A", []Element { AV_A } },
    { "CVSS:3.1/AV:L", "CVSS:3.1/AV:L", []Element { AV_L } },
    { "CVSS:3.1/AV:P", "CVSS:3.1/AV:P", []Element { AV_P } },
    { "CVSS:3.1/AC:H", "CVSS:3.1/AC:H", []Element { AC_H } },
    { "CVSS:3.1/AC:L", "CVSS:3.1/AC:L", []Element { AC_L } },
    { "CVSS:3.1/PR:H", "CVSS:3.1/PR:H", []Element { PR_H } },
    { "CVSS:3.1/PR:L", "CVSS:3.1/PR:L", []Element { PR_L } },
    { "CVSS:3.1/PR:N", "CVSS:3.1/PR:N", []Element { PR_N } },
    { "CVSS:3.1/UI:N", "CVSS:3.1/UI:N", []Element { UI_N } },
    { "CVSS:3.1/UI:R", "CVSS:3.1/UI:R", []Element { UI_R } },
    { "CVSS:3.1/S:U", "CVSS:3.1/S:U", []Element { S_U } },
    { "CVSS:3.1/S:C", "CVSS:3.1/S:C", []Element { S_C } },
    { "CVSS:3.1/C:N", "CVSS:3.1/C:N", []Element { C_N } },
    { "CVSS:3.1/C:L", "CVSS:3.1/C:L", []Element { C_L } },
    { "CVSS:3.1/C:H", "CVSS:3.1/C:H", []Element { C_H } },
    { "CVSS:3.1/I:N", "CVSS:3.1/I:N", []Element { I_N } },
    { "CVSS:3.1/I:L", "CVSS:3.1/I:L", []Element { I_L } },
    { "CVSS:3.1/I:H", "CVSS:3.1/I:H", []Element { I_H } },
    { "CVSS:3.1/A:N", "CVSS:3.1/A:N", []Element { A_N } },
    { "CVSS:3.1/A:L", "CVSS:3.1/A:L", []Element { A_L } },
    { "CVSS:3.1/A:H", "CVSS:3.1/A:H", []Element { A_H } },
    { "CVSS:3.1/E:U", "CVSS:3.1/E:U", []Element { E_U } },
    { "CVSS:3.1/E:P", "CVSS:3.1/E:P", []Element { E_P } },
    { "CVSS:3.1/E:F", "CVSS:3.1/E:F", []Element { E_F } },
    { "CVSS:3.1/E:H", "CVSS:3.1/E:H", []Element { E_H } },
    { "CVSS:3.1/E:X", "CVSS:3.1/E:X", []Element { E_X } },
    { "CVSS:3.1/RL:O", "CVSS:3.1/RL:O", []Element { RL_O } },
    { "CVSS:3.1/RL:T", "CVSS:3.1/RL:T", []Element { RL_T } },
    { "CVSS:3.1/RL:W", "CVSS:3.1/RL:W", []Element { RL_W } },
    { "CVSS:3.1/RL:U", "CVSS:3.1/RL:U", []Element { RL_U } },
    { "CVSS:3.1/RL:X", "CVSS:3.1/RL:X", []Element { RL_X } },
    { "CVSS:3.1/RC:U", "CVSS:3.1/RC:U", []Element { RC_U } },
    { "CVSS:3.1/RC:R", "CVSS:3.1/RC:R", []Element { RC_R } },
    { "CVSS:3.1/RC:C", "CVSS:3.1/RC:C", []Element { RC_C } },
    { "CVSS:3.1/RC:X", "CVSS:3.1/RC:X", []Element { RC_X } },
    { "CVSS:3.1/CR:L", "CVSS:3.1/CR:L", []Element { CR_L } },
    { "CVSS:3.1/CR:M", "CVSS:3.1/CR:M", []Element { CR_M } },
    { "CVSS:3.1/CR:H", "CVSS:3.1/CR:H", []Element { CR_H } },
    { "CVSS:3.1/CR:X", "CVSS:3.1/CR:X", []Element { CR_X } },
    { "CVSS:3.1/IR:L", "CVSS:3.1/IR:L", []Element { IR_L } },
    { "CVSS:3.1/IR:M", "CVSS:3.1/IR:M", []Element { IR_M } },
    { "CVSS:3.1/IR:H", "CVSS:3.1/IR:H", []Element { IR_H } },
    { "CVSS:3.1/IR:X", "CVSS:3.1/IR:X", []Element { IR_X } },
    { "CVSS:3.1/AR:L", "CVSS:3.1/AR:L", []Element { AR_L } },
    { "CVSS:3.1/AR:M", "CVSS:3.1/AR:M", []Element { AR_M } },
    { "CVSS:3.1/AR:H", "CVSS:3.1/AR:H", []Element { AR_H } },
    { "CVSS:3.1/AR:X", "CVSS:3.1/AR:X", []Element { AR_X } },
    { "CVSS:3.1/MAV:N", "CVSS:3.1/MAV:N", []Element { MAV_N } },
    { "CVSS:3.1/MAV:A", "CVSS:3.1/MAV:A", []Element { MAV_A } },
    { "CVSS:3.1/MAV:L", "CVSS:3.1/MAV:L", []Element { MAV_L } },
    { "CVSS:3.1/MAV:P", "CVSS:3.1/MAV:P", []Element { MAV_P } },
    { "CVSS:3.1/MAV:X", "CVSS:3.1/MAV:X", []Element { MAV_X } },
    { "CVSS:3.1/MAC:H", "CVSS:3.1/MAC:H", []Element { MAC_H } },
    { "CVSS:3.1/MAC:L", "CVSS:3.1/MAC:L", []Element { MAC_L } },
    { "CVSS:3.1/MAC:X", "CVSS:3.1/MAC:X", []Element { MAC_X } },
    { "CVSS:3.1/MPR:H", "CVSS:3.1/MPR:H", []Element { MPR_H } },
    { "CVSS:3.1/MPR:L", "CVSS:3.1/MPR:L", []Element { MPR_L } },
    { "CVSS:3.1/MPR:N", "CVSS:3.1/MPR:N", []Element { MPR_N } },
    { "CVSS:3.1/MPR:X", "CVSS:3.1/MPR:X", []Element { MPR_X } },
    { "CVSS:3.1/MUI:N", "CVSS:3.1/MUI:N", []Element { MUI_N } },
    { "CVSS:3.1/MUI:R", "CVSS:3.1/MUI:R", []Element { MUI_R } },
    { "CVSS:3.1/MUI:X", "CVSS:3.1/MUI:X", []Element { MUI_X } },
    { "CVSS:3.1/MS:U", "CVSS:3.1/MS:U", []Element { MS_U } },
    { "CVSS:3.1/MS:C", "CVSS:3.1/MS:C", []Element { MS_C } },
    { "CVSS:3.1/MS:X", "CVSS:3.1/MS:X", []Element { MS_X } },
    { "CVSS:3.1/MC:U", "CVSS:3.1/MC:U", []Element { MC_U } },
    { "CVSS:3.1/MC:C", "CVSS:3.1/MC:C", []Element { MC_C } },
    { "CVSS:3.1/MC:N", "CVSS:3.1/MC:N", []Element { MC_N } },
    { "CVSS:3.1/MC:L", "CVSS:3.1/MC:L", []Element { MC_L } },
    { "CVSS:3.1/MC:H", "CVSS:3.1/MC:H", []Element { MC_H } },
    { "CVSS:3.1/MC:X", "CVSS:3.1/MC:X", []Element { MC_X } },
    { "CVSS:3.1/MI:U", "CVSS:3.1/MI:U", []Element { MI_U } },
    { "CVSS:3.1/MI:C", "CVSS:3.1/MI:C", []Element { MI_C } },
    { "CVSS:3.1/MI:N", "CVSS:3.1/MI:N", []Element { MI_N } },
    { "CVSS:3.1/MI:L", "CVSS:3.1/MI:L", []Element { MI_L } },
    { "CVSS:3.1/MI:H", "CVSS:3.1/MI:H", []Element { MI_H } },
    { "CVSS:3.1/MI:X", "CVSS:3.1/MI:X", []Element { MI_X } },
    { "CVSS:3.1/MA:U", "CVSS:3.1/MA:U", []Element { MA_U } },
    { "CVSS:3.1/MA:C", "CVSS:3.1/MA:C", []Element { MA_C } },
    { "CVSS:3.1/MA:N", "CVSS:3.1/MA:N", []Element { MA_N } },
    { "CVSS:3.1/MA:L", "CVSS:3.1/MA:L", []Element { MA_L } },
    { "CVSS:3.1/MA:H", "CVSS:3.1/MA:H", []Element { MA_H } },
    { "CVSS:3.1/MA:X", "CVSS:3.1/MA:X", []Element { MA_X } },
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
        exp := test.expStr
        got := vec.String()
        if got != exp {
          t.Fatalf("got \"%s\", exp \"%s\"", got, exp)
        }
      })

      // check elements
      t.Run("elements", func(t *testing.T) {
        exp := test.expEls
        got := vec.Elements()
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
    name: "wrong version",
    val: "CVSS:3.0/AV:N",
  }, {
    name: "invalid element",
    val: "CVSS:3.0/foo",
  }, {
    name: "duplicate element",
    val: "CVSS:3.1/AV:N/AV:A",
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
