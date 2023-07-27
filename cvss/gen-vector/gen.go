//go:build exclude
//
// gen.go: generate CVSS vector code.
//
// Used to generate the following files:
// - cvss/v2/vector.go
// - cvss/v30/vector.go
// - cvss/v31/vector.go
//
// Example:
//
//     # generate cvss/v2/vector.go
//     go run cvss/gen-vector/gen.go v2 > cvss/v2/vector.go
//
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

type metricKey struct {
  Id, Name string // id and name of metric key
  Shift, Mask uint8 // bit offset and size within vector uint64
  Enum string // enumeration name
}

// Template parameters.
type TemplateParams struct {
  Ns string // namespace
  Version string // version string
  Pack string // packed string
  Offsets map[string]int // map of string to byte offset in packed string
  Defs map[string]Enum // enum definitions
  Keys []metricKey // metric keys
  Vals []Value // values
}

// CVSS version metadata
type Version struct {
  ns string // output namespace
  version string // version string
  defs map[string]Enum // enum definitions
  enums []string // ordered list of enums
  keys []metricKey // metric keys
}

// map of version ID to version metadata.
var versions = map[string]Version {
  "v2": Version {
    ns: "v2", // namespace
    version: "2", // version string

    // enum definitions
    defs: map[string]Enum {
      "AccessVector": Enum {
        "AV",
        "AccessVector",
        []Value {
          { "N", "Network", "NETWORK" },
          { "A", "AdjacentNetwork", "ADJACENT_NETWORK" },
          { "L", "Local", "LOCAL" },
        },
      },

      "AccessComplexity": Enum {
        "AC",
        "AccessComplexity",
        []Value {
          { "H", "High", "HIGH" },
          { "M", "Medium", "MEDIUM" },
          { "L", "Low", "LOW" },
        },
      },

      "Authentication": Enum {
        "Au",
        "Authentication",
        []Value {
          { "M", "Multiple", "MULTIPLE" },
          { "S", "Single", "SINGLE" },
          { "N", "None", "NONE" },
        },
      },

      "Impact": Enum {
        "I",
        "Impact",
        []Value {
          { "N", "None", "NONE" },
          { "P", "Partial", "PARTIAL" },
          { "C", "Complete", "COMPLETE" },
        },
      },

      "Exploitability": Enum {
        "E",
        "Exploitability",
        []Value {
          { "U", "Unproven", "UNPROVEN" },
          { "POC", "ProofOfConcept", "PROOF_OF_CONCEPT" },
          { "F", "Functional", "FUNCTIONAL" },
          { "H", "High", "HIGH" },
          { "ND", "NotDefined", "NOT_DEFINED" },
        },
      },

      "RemediationLevel": Enum {
        "RL",
        "RemediationLevel",
        []Value {
          { "OF", "OfficialFix", "OFFICIAL_FIX" },
          { "TF", "TemporaryFix", "TEMPORARY_FIX" },
          { "W", "Workaround", "WORKAROUND" },
          { "U", "Unavailable", "UNAVAILABLE" },
          { "ND", "NotDefined", "NOT_DEFINED" },
        },
      },

      "ReportConfidence": Enum {
        "RC",
        "ReportConfidence",
        []Value {
          { "UC", "Unconfirmed", "UNCONFIRMED" },
          { "UR", "Uncorroborated", "UNCORROBORATED" },
          { "C", "Confirmed", "CONFIRMED" },
          { "ND", "NotDefined", "NOT_DEFINED" },
        },
      },

      "CollateralDamagePotential": Enum {
        "CDP",
        "CollateralDamagePotential",
        []Value {
          { "N", "None", "NONE" },
          { "L", "Low", "LOW" },
          { "LM", "LowMedium", "LOW_MEDIUM" },
          { "MH", "MediumHigh", "MEDIUM_HIGH" },
          { "H", "High", "HIGH" },
          { "ND", "NotDefined", "NOT_DEFINED" },
        },
      },

      "TargetDistribution": Enum {
        "TD",
        "TargetDistribution",
        []Value {
          { "N", "None", "NONE" },
          { "L", "Low", "LOW" },
          { "M", "Medium", "MEDIUM" },
          { "H", "High", "HIGH" },
          { "ND", "NotDefined", "NOT_DEFINED" },
        },
      },

      "Requirement": Enum {
        "R",
        "Requirement",
        []Value {
          { "L", "Low", "LOW" },
          { "M", "Medium", "MEDIUM" },
          { "H", "High", "HIGH" },
          { "ND", "NotDefined", "NOT_DEFINED" },
        },
      },
    },

    // Ordered list of enums
    enums: []string {
      "AccessVector",
      "AccessComplexity",
      "Authentication",
      "Impact",
      "Exploitability",
      "RemediationLevel",
      "ReportConfidence",
      "CollateralDamagePotential",
      "TargetDistribution",
      "Requirement",
    },

    // metric keys
    keys: []metricKey {
      { "AV", "Access Vector", 0, 2, "AccessVector" },
      { "AC", "Access Complexity", 2, 2, "AccessComplexity" },
      { "Au", "Authentication", 4, 2, "Authentication" },
      { "C", "Confidentiality Impact", 6, 2, "Impact" },
      { "I", "Integrity Impact", 8, 2, "Impact" },
      { "A", "Availability Impact", 10, 2, "Impact" },
      { "E", "Exploitability", 12, 3, "Exploitability" },
      { "RL", "Remediation Level", 15, 3, "RemediationLevel" },
      { "RC", "Report Confidence", 18, 3, "ReportConfidence" },
      { "CDP", "Collateral Damage Potential", 21, 3, "CollateralDamagePotential" },
      { "TD", "Target Distribution", 24, 3, "TargetDistribution" },
      { "CR", "Confidentiality Requirement", 27, 3, "Requirement" },
      { "IR", "Integrity Requirement", 30, 3, "Requirement" },
      { "AR", "Availability Requirement", 33, 3, "Requirement" },
    },
  },

  "v30": Version {
    ns: "v30", // namespace
    version: "3.0", // version string

    // enum definitions
    defs: map[string]Enum {
      "AttackVector": Enum {
        "AV",
        "AttackVector",
        []Value {
          { "N", "Network", "NETWORK" },
          { "A", "AdjacentNetwork", "ADJACENT_NETWORK" },
          { "L", "Local", "LOCAL" },
          { "P", "Physical", "PHYSICAL" },
        },
      },

      "ModifiedAttackVector": Enum {
        "MAV",
        "ModifiedAttackVector",
        []Value {
          { "N", "Network", "NETWORK" },
          { "A", "AdjacentNetwork", "ADJACENT_NETWORK" },
          { "L", "Local", "LOCAL" },
          { "P", "Physical", "PHYSICAL" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "AttackComplexity": Enum {
        "AC",
        "AttackComplexity",
        []Value {
          { "H", "High", "HIGH" },
          { "L", "Low", "LOW" },
        },
      },

      "ModifiedAttackComplexity": Enum {
        "MAC",
        "ModifiedAttackComplexity",
        []Value {
          { "H", "High", "HIGH" },
          { "L", "Low", "LOW" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "PrivilegesRequired": Enum {
        "PR",
        "PrivilegesRequired",
        []Value {
          { "H", "High", "HIGH" },
          { "L", "Low", "LOW" },
          { "N", "None", "NONE" },
        },
      },

      "ModifiedPrivilegesRequired": Enum {
        "MPR",
        "ModifiedPrivilegesRequired",
        []Value {
          { "H", "High", "HIGH" },
          { "L", "Low", "LOW" },
          { "N", "None", "NONE" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "UserInteraction": Enum {
        "UI",
        "UserInteraction",
        []Value {
          { "N", "None", "NONE" },
          { "R", "Required", "REQUIRED" },
        },
      },

      "ModifiedUserInteraction": Enum {
        "MUI",
        "ModifiedUserInteraction",
        []Value {
          { "N", "None", "NONE" },
          { "R", "Required", "REQUIRED" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "Scope": Enum {
        "S",
        "Scope",
        []Value {
          { "U", "Unchanged", "UNCHANGED" },
          { "C", "Changed", "CHANGED" },
        },
      },

      "ModifiedScope": Enum {
        "MS",
        "ModifiedScope",
        []Value {
          { "U", "Unchanged", "UNCHANGED" },
          { "C", "Changed", "CHANGED" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "Impact": Enum {
        "I",
        "Impact",
        []Value {
          { "N", "None", "NONE" },
          { "L", "Low", "LOW" },
          { "H", "High", "HIGH" },
        },
      },

      "ModifiedImpact": Enum {
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
      },

      "ExploitCodeMaturity": Enum {
        "E",
        "ExploitCodeMaturity",
        []Value {
          { "U", "Unproven", "UNPROVEN" },
          { "P", "ProofOfConcept", "PROOF_OF_CONCEPT" },
          { "F", "Functional", "FUNCTIONAL" },
          { "H", "High", "HIGH" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "RemediationLevel": Enum {
        "RL",
        "RemediationLevel",
        []Value {
          { "O", "OfficialFix", "OFFICIAL_FIX" },
          { "T", "TemporaryFix", "TEMPORARY_FIX" },
          { "W", "Workaround", "WORKAROUND" },
          { "U", "Unavailable", "UNAVAILABLE" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "Confidence": Enum {
        "C",
        "Confidence",
        []Value {
          { "U", "Unknown", "UNKNOWN" },
          { "R", "Reasonable", "REASONABLE" },
          { "C", "Confirmed", "CONFIRMED" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "Requirement": Enum {
        "R",
        "Requirement",
        []Value {
          { "L", "Low", "LOW" },
          { "M", "Medium", "MEDIUM" },
          { "H", "High", "HIGH" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },
    },

    // ordered list of enums
    enums: []string {
      "AttackVector",
      "ModifiedAttackVector",
      "AttackComplexity",
      "ModifiedAttackComplexity",
      "PrivilegesRequired",
      "ModifiedPrivilegesRequired",
      "UserInteraction",
      "ModifiedUserInteraction",
      "Scope",
      "ModifiedScope",
      "Impact",
      "ModifiedImpact",
      "ExploitCodeMaturity",
      "RemediationLevel",
      "Confidence",
      "Requirement",
    },

    // metric keys
    keys: []metricKey {
      { "AV", "Attack Vector", 0, 3, "AttackVector" },
      { "AC", "Attack Complexity", 3, 2, "AttackComplexity" },
      { "PR", "Privileges Required", 5, 2, "PrivilegesRequired" },
      { "UI", "User Interaction", 7, 2, "UserInteraction" },
      { "S", "Scope", 9, 2, "Scope" },
      { "C", "Confidentiality Impact", 11, 2, "Impact" },
      { "I", "Integrity Impact", 13, 2, "Impact" },
      { "A", "Availability Impact", 15, 2, "Impact" },
      { "E", "Exploit Code Maturity", 17, 3, "ExploitCodeMaturity" },
      { "RL", "Remediation Level", 20, 3, "RemediationLevel" },
      { "RC", "Report Confidence", 23, 3, "Confidence" },
      { "CR", "Confidentiality Requirement", 26, 3, "Requirement" },
      { "IR", "Integrity Requirement", 29, 3, "Requirement" },
      { "AR", "Availability Requirement", 32, 3, "Requirement" },
      { "MAV", "Modified Attack Vector", 35, 3, "ModifiedAttackVector" },
      { "MAC", "Modified Attack Complexity", 38, 2, "ModifiedAttackComplexity" },
      { "MPR", "Modified Privileges Required", 40, 3, "ModifiedPrivilegesRequired" },
      { "MUI", "Modified User Interaction", 43, 2, "ModifiedUserInteraction" },
      { "MS", "Modified Scope", 45, 2, "ModifiedScope" },
      { "MC", "Modified Confidentiality Impact", 47, 3, "ModifiedImpact" },
      { "MI", "Modified Integrity Impact", 50, 3, "ModifiedImpact" },
      { "MA", "Modified Availability Impact", 53, 3, "ModifiedImpact" },
    },
  },

  "v31": Version {
    ns: "v31", // namespace
    version: "3.1", // version string

    // enum definitions
    defs: map[string]Enum {
      "AttackVector": Enum {
        "AV",
        "AttackVector",
        []Value {
          { "N", "Network", "NETWORK" },
          { "A", "AdjacentNetwork", "ADJACENT_NETWORK" },
          { "L", "Local", "LOCAL" },
          { "P", "Physical", "PHYSICAL" },
        },
      },

      "ModifiedAttackVector": Enum {
        "MAV",
        "ModifiedAttackVector",
        []Value {
          { "N", "Network", "NETWORK" },
          { "A", "AdjacentNetwork", "ADJACENT_NETWORK" },
          { "L", "Local", "LOCAL" },
          { "P", "Physical", "PHYSICAL" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "AttackComplexity": Enum {
        "AC",
        "AttackComplexity",
        []Value {
          { "H", "High", "HIGH" },
          { "L", "Low", "LOW" },
        },
      },

      "ModifiedAttackComplexity": Enum {
        "MAC",
        "ModifiedAttackComplexity",
        []Value {
          { "H", "High", "HIGH" },
          { "L", "Low", "LOW" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "PrivilegesRequired": Enum {
        "PR",
        "PrivilegesRequired",
        []Value {
          { "H", "High", "HIGH" },
          { "L", "Low", "LOW" },
          { "N", "None", "NONE" },
        },
      },

      "ModifiedPrivilegesRequired": Enum {
        "MPR",
        "ModifiedPrivilegesRequired",
        []Value {
          { "H", "High", "HIGH" },
          { "L", "Low", "LOW" },
          { "N", "None", "NONE" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "UserInteraction": Enum {
        "UI",
        "UserInteraction",
        []Value {
          { "N", "None", "NONE" },
          { "R", "Required", "REQUIRED" },
        },
      },

      "ModifiedUserInteraction": Enum {
        "MUI",
        "ModifiedUserInteraction",
        []Value {
          { "N", "None", "NONE" },
          { "R", "Required", "REQUIRED" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "Scope": Enum {
        "S",
        "Scope",
        []Value {
          { "U", "Unchanged", "UNCHANGED" },
          { "C", "Changed", "CHANGED" },
        },
      },

      "ModifiedScope": Enum {
        "MS",
        "ModifiedScope",
        []Value {
          { "U", "Unchanged", "UNCHANGED" },
          { "C", "Changed", "CHANGED" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "Impact": Enum {
        "I",
        "Impact",
        []Value {
          { "N", "None", "NONE" },
          { "L", "Low", "LOW" },
          { "H", "High", "HIGH" },
        },
      },

      "ModifiedImpact": Enum {
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
      },

      "ExploitCodeMaturity": Enum {
        "E",
        "ExploitCodeMaturity",
        []Value {
          { "U", "Unproven", "UNPROVEN" },
          { "P", "ProofOfConcept", "PROOF_OF_CONCEPT" },
          { "F", "Functional", "FUNCTIONAL" },
          { "H", "High", "HIGH" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "RemediationLevel": Enum {
        "RL",
        "RemediationLevel",
        []Value {
          { "O", "OfficialFix", "OFFICIAL_FIX" },
          { "T", "TemporaryFix", "TEMPORARY_FIX" },
          { "W", "Workaround", "WORKAROUND" },
          { "U", "Unavailable", "UNAVAILABLE" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "Confidence": Enum {
        "C",
        "Confidence",
        []Value {
          { "U", "Unknown", "UNKNOWN" },
          { "R", "Reasonable", "REASONABLE" },
          { "C", "Confirmed", "CONFIRMED" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },

      "Requirement": Enum {
        "R",
        "Requirement",
        []Value {
          { "L", "Low", "LOW" },
          { "M", "Medium", "MEDIUM" },
          { "H", "High", "HIGH" },
          { "X", "NotDefined", "NOT_DEFINED" },
        },
      },
    },

    // ordered list of enums
    enums: []string {
      "AttackVector",
      "ModifiedAttackVector",
      "AttackComplexity",
      "ModifiedAttackComplexity",
      "PrivilegesRequired",
      "ModifiedPrivilegesRequired",
      "UserInteraction",
      "ModifiedUserInteraction",
      "Scope",
      "ModifiedScope",
      "Impact",
      "ModifiedImpact",
      "ExploitCodeMaturity",
      "RemediationLevel",
      "Confidence",
      "Requirement",
    },

    // metric keys
    keys: []metricKey {
      { "AV", "Attack Vector", 0, 3, "AttackVector" },
      { "AC", "Attack Complexity", 3, 2, "AttackComplexity" },
      { "PR", "Privileges Required", 5, 2, "PrivilegesRequired" },
      { "UI", "User Interaction", 7, 2, "UserInteraction" },
      { "S", "Scope", 9, 2, "Scope" },
      { "C", "Confidentiality Impact", 11, 2, "Impact" },
      { "I", "Integrity Impact", 13, 2, "Impact" },
      { "A", "Availability Impact", 15, 2, "Impact" },
      { "E", "Exploit Code Maturity", 17, 3, "ExploitCodeMaturity" },
      { "RL", "Remediation Level", 20, 3, "RemediationLevel" },
      { "RC", "Report Confidence", 23, 3, "Confidence" },
      { "CR", "Confidentiality Requirement", 26, 3, "Requirement" },
      { "IR", "Integrity Requirement", 29, 3, "Requirement" },
      { "AR", "Availability Requirement", 32, 3, "Requirement" },
      { "MAV", "Modified Attack Vector", 35, 3, "ModifiedAttackVector" },
      { "MAC", "Modified Attack Complexity", 38, 2, "ModifiedAttackComplexity" },
      { "MPR", "Modified Privileges Required", 40, 3, "ModifiedPrivilegesRequired" },
      { "MUI", "Modified User Interaction", 43, 2, "ModifiedUserInteraction" },
      { "MS", "Modified Scope", 45, 2, "ModifiedScope" },
      { "MC", "Modified Confidentiality Impact", 47, 3, "ModifiedImpact" },
      { "MI", "Modified Integrity Impact", 50, 3, "ModifiedImpact" },
      { "MA", "Modified Availability Impact", 53, 3, "ModifiedImpact" },
    },
  },
}

// Get packed string of strings and offset map.
func (v Version) getPack() (string, map[string]int) {
  // build lut of strings
  lut := map[string]bool {}
  for _, k := range(v.keys) {
    lut[k.Id] = true
    lut[k.Name] = true

    // add enumeration values
    for _, v := range(v.defs[k.Enum].Values) {
      lut[v.Id] = true
      lut[v.Name] = true

      // add metric name
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
func (version Version) getVals() []Value {
  lut := map[string]Value {}
  for _, e := range(version.enums) {
    for _, v := range(version.defs[e].Values) {
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

// Get template parameters from version metadata.
func (v Version) Params() TemplateParams {
  pack, offsets := v.getPack() // get packed string and offset map
  vals := v.getVals() // get values

  // build/return template parameters
  return TemplateParams {
    Ns: v.ns,
    Version: v.version,
    Pack: pack,
    Offsets: offsets,
    Defs: v.defs,
    Keys: v.keys,
    Vals: vals,
  }
}

// template functions
var fns = template.FuncMap {
  "packed_metrics": func(id string, vals []Value) []string {
    r := []string { "invalidMetric" }

    for i := 0; i < 7; i += 1 {
      if i < len(vals) {
        r = append(r, fmt.Sprintf("%s_%s", id, vals[i].Id))
      } else {
        r = append(r, "invalidMetric")
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

func main() {
  // check args
  if len(os.Args) < 2 {
    log.Fatalf("Usage: %s <versionId>", appName())
  }

  // get version ID from arguments
  id := os.Args[1]

  // get version from version ID
  version, ok := versions[id]
  if !ok {
    log.Fatalf("Unknwon version ID: %s", id)
  }

  // expand template, write to stdout
  if err := t.Execute(os.Stdout, version.Params()); err != nil {
    log.Fatal(err)
  }
}
