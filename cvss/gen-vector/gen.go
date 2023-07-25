//go:build exclude
//
// gen.go: generate cvss vector code.
package main

import (
  "fmt"
  "log"
  "os"
  "strings"
  "sort"
  "text/template"
  _ "embed"
)

// Enumeration value.
type Value struct { Id, Name, Title string }

// Enumeration.
type Enum struct { Id, Name string; Values []Value }

var AttackVector = Enum {
  "AV",
  "AttackVector",
  []Value {
    { "N", "Network", "NETWORK" },
    { "A", "AdjacentNetwork", "ADJACENT_NETWORK" },
    { "L", "Local", "LOCAL" },
    { "P", "Physical", "PHYSICAL" },
  },
}

var ModifiedAttackVector = Enum {
  "MAV",
  "ModifiedAttackVector",
  []Value {
    { "N", "Network", "NETWORK" },
    { "A", "AdjacentNetwork", "ADJACENT_NETWORK" },
    { "L", "Local", "LOCAL" },
    { "P", "Physical", "PHYSICAL" },
    { "X", "NotDefined", "NOT_DEFINED" },
  },
}

var AttackComplexity = Enum {
  "AC",
  "AttackComplexity",
  []Value {
    { "H", "High", "HIGH" },
    { "L", "Low", "LOW" },
  },
}

var ModifiedAttackComplexity = Enum {
  "MAC",
  "ModifiedAttackComplexity",
  []Value {
    { "H", "High", "HIGH" },
    { "L", "Low", "LOW" },
    { "X", "NotDefined", "NOT_DEFINED" },
  },
}

var PrivilegesRequired = Enum {
  "PR",
  "PrivilegesRequired",
  []Value {
    { "H", "High", "HIGH" },
    { "L", "Low", "LOW" },
    { "N", "None", "NONE" },
  },
}

var ModifiedPrivilegesRequired = Enum {
  "MPR",
  "ModifiedPrivilegesRequired",
  []Value {
    { "H", "High", "HIGH" },
    { "L", "Low", "LOW" },
    { "N", "None", "NONE" },
    { "X", "NotDefined", "NOT_DEFINED" },
  },
}

var UserInteraction = Enum {
  "UI",
  "UserInteraction",
  []Value {
    { "N", "None", "NONE" },
    { "R", "Required", "REQUIRED" },
  },
}

var ModifiedUserInteraction = Enum {
  "MUI",
  "ModifiedUserInteraction",
  []Value {
    { "N", "None", "NONE" },
    { "R", "Required", "REQUIRED" },
    { "X", "NotDefined", "NOT_DEFINED" },
  },
}

var Scope = Enum {
  "S",
  "Scope",
  []Value {
    { "U", "Unchanged", "UNCHANGED" },
    { "C", "Changed", "CHANGED" },
  },
}

var ModifiedScope = Enum {
  "MS",
  "ModifiedScope",
  []Value {
    { "U", "Unchanged", "UNCHANGED" },
    { "C", "Changed", "CHANGED" },
    { "X", "NotDefined", "NOT_DEFINED" },
  },
}

var Impact = Enum {
  "I",
  "Impact",
  []Value {
    { "N", "None", "NONE" },
    { "L", "Low", "LOW" },
    { "H", "High", "HIGH" },
  },
}

var ModifiedImpact = Enum {
  "MI",
  "ModifiedImpact",
  []Value {
    { "U", "Unchanged", "UNCHANGED" },
    { "C", "Changed", "CHANGED" },
    { "N", "None", "NONE" },
    { "L", "Low", "LOW" },
    { "H", "High", "HIGH" },
    { "X", "NotDefined", "NOT_DEFINED" },
  },
}

var ExploitCodeMaturity = Enum {
  "E",
  "ExploitCodeMaturity",
  []Value {
    { "U", "Unproven", "UNPROVEN" },
    { "P", "ProofOfConcept", "PROOF_OF_CONCEPT" },
    { "F", "Functional", "FUNCTIONAL" },
    { "H", "High", "HIGH" },
    { "X", "NotDefined", "NOT_DEFINED" },
  },
}

var RemediationLevel = Enum {
  "RL",
  "RemediationLevel",
  []Value {
    { "O", "OfficialFix", "OFFICIAL_FIX" },
    { "T", "TemporaryFix", "TEMPORARY_FIX" },
    { "W", "Workaround", "WORKAROUND" },
    { "U", "Unavailable", "UNAVAILABLE" },
    { "X", "NotDefined", "NOT_DEFINED" },
  },
}

var Confidence = Enum {
  "C",
  "Confidence",
  []Value {
    { "U", "Unknown", "UNKNOWN" },
    { "R", "Reasonable", "REASONABLE" },
    { "C", "Confirmed", "CONFIRMED" },
    { "X", "NotDefined", "NOT_DEFINED" },
  },
}

var Requirement = Enum {
  "R",
  "Requirement",
  []Value {
    { "L", "Low", "LOW" },
    { "M", "Medium", "MEDIUM" },
    { "H", "High", "HIGH" },
    { "X", "NotDefined", "NOT_DEFINED" },
  },
}

// list of vector enums
var enums = []Enum {
  AttackVector,
  ModifiedAttackVector,
  AttackComplexity,
  ModifiedAttackComplexity,
  PrivilegesRequired,
  ModifiedPrivilegesRequired,
  UserInteraction,
  ModifiedUserInteraction,
  Scope,
  ModifiedScope,
  Impact,
  ModifiedImpact,
  ExploitCodeMaturity,
  RemediationLevel,
  Confidence,
  Requirement,
}

// vector keys
var keys = []struct {
  Id, Name string
  Shift, Mask uint8
  Enum Enum
} {
  { "AV", "Attack Vector", 0, 3, AttackVector },
  { "AC", "Attack Complexity", 3, 2, AttackComplexity },
  { "PR", "Privileges Required", 5, 2, PrivilegesRequired },
  { "UI", "User Interaction", 7, 2, UserInteraction },
  { "S", "Scope", 9, 2, Scope },
  { "C", "Confidentiality Impact", 11, 2, Impact },
  { "I", "Integrity Impact", 13, 2, Impact },
  { "A", "Availability Impact", 15, 2, Impact },
  { "E", "Exploit Code Maturity", 17, 3, ExploitCodeMaturity },
  { "RL", "Remediation Level", 20, 3, RemediationLevel },
  { "RC", "Report Confidence", 23, 3, Confidence },
  { "CR", "Confidentiality Requirement", 26, 3, Requirement },
  { "IR", "Integrity Requirement", 29, 3, Requirement },
  { "AR", "Availability Requirement", 32, 3, Requirement },
  { "MAV", "Modified Attack Vector", 35, 3, ModifiedAttackVector },
  { "MAC", "Modified Attack Complexity", 38, 2, ModifiedAttackComplexity },
  { "MPR", "Modified Privileges Required", 40, 3, ModifiedPrivilegesRequired },
  { "MUI", "Modified User Interaction", 43, 2, ModifiedUserInteraction },
  { "MS", "Modified Scope", 45, 2, ModifiedScope },
  { "MC", "Modified Confidentiality Impact", 47, 3, ModifiedImpact },
  { "MI", "Modified Integrity Impact", 50, 3, ModifiedImpact },
  { "MA", "Modified Availability Impact", 53, 3, ModifiedImpact },
}

// template functions
var fns = template.FuncMap {
  "packed_elements": func(id string, vals []Value) []string {
    r := []string { "invalidElement" }

    for i := 0; i < 7; i += 1 {
      if i < len(vals) {
        r = append(r, fmt.Sprintf("%s_%s", id, vals[i].Id))
      } else {
        r = append(r, "invalidElement")
      }
    }

    return r
  },
}

//go:embed code.tmpl
var CODE string

// build code template
var t = template.Must(template.New("").Funcs(fns).Parse(CODE))

// get application name from command-line arguments
func appName() string {
  if len(os.Args) > 0 {
    return os.Args[0]
  } else {
    return "gen-vector"
  }
}

// Get packed string of strings and offset map.
func getPack() (string, map[string]int) {
  // build lut of strings
  lut := map[string]bool{}
  for _, k := range(keys) {
    lut[k.Id] = true
    lut[k.Name] = true

    // add enumeration values
    for _, v := range(k.Enum.Values) {
      lut[v.Id] = true
      lut[v.Name] = true
      lut[v.Title] = true

      // add element name
      lut[fmt.Sprintf("%s:%s", k.Id, v.Id)] = true
    }
  }

  // build complete list of strings
  strs := make([]string, 0, len(lut))
  for k := range(lut) {
    strs = append(strs, k)
  }

  // sort strings from longest to shortest
  sort.Slice(strs, func(ai, bi int) bool {
    a := strs[ai]
    b := strs[bi]

    // sort longer strings first, and sort strings of the same length
    // alphabetically
    return len(a) > len(b) || (len(a) == len(b) && strings.Compare(a, b) == -1)
  })

  // join into packed string, build offset lut
  pack := ""
  offsets := map[string]int {}
  for _, s := range(strs) {
    ofs := strings.Index(pack, s)
    if ofs == -1 {
      ofs = len(pack)
      pack = pack + s // append to packed string
    }
    offsets[s] = ofs
  }

  // return results
  return pack, offsets
}

// Get sorted array of possible values
func getVals() []Value {
  lut := map[string]Value {}
  for _, e := range(enums) {
    for _, v := range(e.Values) {
      lut[v.Name] = v
    }
  }

  // build sorted list of value names
  names := make([]string, 0, len(lut))
  for name := range(lut) {
    names = append(names, name)
  }
  sort.Strings(names)

  // build sorted list of values
  r := make([]Value, 0, len(lut))
  for i := range(names) {
    r = append(r, lut[names[i]])
  }

  // return result
  return r
}

func main() {
  if len(os.Args) < 2 {
    log.Fatalf("Usage: %s <packageName>", appName())
  }

  // get packed string and a map of offsets
  pack, offsets := getPack()

  // build template args
  args := map[string]any {
    "ns": os.Args[1],
    "pack": pack,
    "offsets": offsets,
    "enums": enums,
    "keys": keys,
    "vals": getVals(),
  }

  // expand template, write to stdout
  if err := t.Execute(os.Stdout, args); err != nil {
    log.Fatal(err)
  }
}
