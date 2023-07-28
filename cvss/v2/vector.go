

// CVSS v2 key, value, metrics, and vectors.
//
// Automatically generated by "cvss/gen-vector/gen.go".
package v2

import (
  "encoding/json"
  "fmt"
  "strings"
)

// packed strings
const pack = "Collateral Damage PotentialConfidentiality RequirementAvailability RequirementConfidentiality ImpactIntegrity RequirementAvailability ImpactTarget DistributionAccess ComplexityRemediation LevelReport ConfidenceIntegrity ImpactAdjacentNetworkAuthenticationExploitabilityProofOfConceptUncorroboratedAccess VectorTemporaryFixOfficialFixUnavailableUnconfirmedFunctionalMediumHighNotDefinedWorkaroundConfirmedLowMediumCompleteMultipleUnprovenPartialCDP:LMCDP:MHCDP:NDSingleAR:NDCDP:HCR:NDE:POCIR:NDLocalRC:NDRC:UCRC:URRL:NDRL:OFRL:TFTD:NDAC:HAC:LAC:MAR:HAR:LAR:MAV:AAV:LAV:NAu:MAu:NAu:SCR:HCR:LCR:ME:NDIR:HIR:LIR:MNoneRC:CRL:URL:WTD:HTD:LTD:MA:CA:NA:PC:PE:FE:HE:UI:CI:NI:P"

// offset and length of packed Key strings
var keys = [...]struct {
  idOfs, idLen uint16 // id string offset and length
  nameOfs, nameLen uint16 // name string offset and length
} {
  { 0, 0, 0, 0 }, // invalidKey
  { 557, 2, 297, 13 },  // Access Vector
  { 533, 2, 159, 17 },  // Access Complexity
  { 241, 2, 241, 14 },  // Authentication
  { 0, 1, 78, 22 },  // Confidentiality Impact
  { 94, 1, 210, 16 },  // Integrity Impact
  { 54, 1, 121, 19 },  // Availability Impact
  { 255, 1, 255, 14 },  // Exploitability
  { 513, 2, 176, 17 },  // Remediation Level
  { 498, 2, 193, 17 },  // Report Confidence
  { 444, 3, 0, 27 },  // Collateral Damage Potential
  { 528, 2, 140, 19 },  // Target Distribution
  { 478, 2, 27, 27 },  // Confidentiality Requirement
  { 488, 2, 100, 21 },  // Integrity Requirement
  { 468, 2, 54, 24 },  // Availability Requirement
}

// Metric key.
type Key uint8
const (
  invalidKey Key = iota
  AV // Access Vector
  AC // Access Complexity
  Au // Authentication
  C // Confidentiality Impact
  I // Integrity Impact
  A // Availability Impact
  E // Exploitability
  RL // Remediation Level
  RC // Report Confidence
  CDP // Collateral Damage Potential
  TD // Target Distribution
  CR // Confidentiality Requirement
  IR // Integrity Requirement
  AR // Availability Requirement
  lastKey
)

// Convert Key to string.
func (k Key) String() string {
  if uint8(k) < uint8(lastKey) {
    d := keys[uint8(k)]
    return pack[d.idOfs:(d.idOfs+d.idLen)]
  } else {
    return ""
  }
}

// Convert Key to name string.
func (k Key) Name() string {
  if uint8(k) < uint8(lastKey) {
    d := keys[uint8(k)]
    return pack[d.nameOfs:(d.nameOfs+d.nameLen)]
  } else {
    return ""
  }
}

// offset and length of ID and name strings in packed string.
var values = [...]struct {
  idOfs, idLen uint16
  nameOfs, nameLen uint16
} {
  { 0, 0, 0, 0 }, // invalidValue
  { 54, 1, 226, 15 }, // AdjacentNetwork
  { 0, 1, 413, 8 }, // Complete
  { 0, 1, 395, 9 }, // Confirmed
  { 319, 1, 355, 10 }, // Functional
  { 371, 1, 371, 4 }, // High
  { 188, 1, 493, 5 }, // Local
  { 188, 1, 404, 3 }, // Low
  { 448, 2, 404, 9 }, // LowMedium
  { 365, 1, 365, 6 }, // Medium
  { 454, 2, 365, 10 }, // MediumHigh
  { 365, 1, 421, 8 }, // Multiple
  { 234, 1, 234, 7 }, // Network
  { 234, 1, 609, 4 }, // None
  { 460, 2, 375, 10 }, // NotDefined
  { 521, 2, 322, 11 }, // OfficialFix
  { 18, 1, 437, 7 }, // Partial
  { 485, 3, 269, 14 }, // ProofOfConcept
  { 462, 1, 462, 6 }, // Single
  { 526, 2, 310, 12 }, // TemporaryFix
  { 283, 1, 333, 11 }, // Unavailable
  { 506, 2, 344, 11 }, // Unconfirmed
  { 511, 2, 283, 14 }, // Uncorroborated
  { 283, 1, 429, 8 }, // Unproven
  { 385, 1, 385, 10 }, // Workaround
}

// Metric value.
type Value uint8
const (
  invalidValue Value = iota
  AdjacentNetwork // A
  Complete // C
  Confirmed // C
  Functional // F
  High // H
  Local // L
  Low // L
  LowMedium // LM
  Medium // M
  MediumHigh // MH
  Multiple // M
  Network // N
  None // N
  NotDefined // ND
  OfficialFix // OF
  Partial // P
  ProofOfConcept // POC
  Single // S
  TemporaryFix // TF
  Unavailable // U
  Unconfirmed // UC
  Uncorroborated // UR
  Unproven // U
  Workaround // W
  lastValue
)

// Convert Value to ID string.
func (v Value) String() string {
  if uint8(v) < uint8(lastValue) {
    d := values[uint8(v)]
    return pack[d.idOfs:(d.idOfs+d.idLen)]
  } else {
    return ""
  }
}

// Convert Value to name string.
func (v Value) Name() string {
  if uint8(v) < uint8(lastValue) {
    d := values[uint8(v)]
    return pack[d.nameOfs:(d.nameOfs + d.nameLen)]
  } else {
    return ""
  }
}

// metrics
var metrics = [...]struct {
  Key Key // metric key
  Value Value // metric value
  strOfs, strLen uint16 // offset and length of packed metric strings
} {
  { invalidKey, invalidValue, 0, 0 }, // invalidMetric
    { AV, Network, 565, (2 + 1 + 1) }, // AV_N
    { AV, AdjacentNetwork, 557, (2 + 1 + 1) }, // AV_A
    { AV, Local, 561, (2 + 1 + 1) }, // AV_L
    { AC, High, 533, (2 + 1 + 1) }, // AC_H
    { AC, Medium, 541, (2 + 1 + 1) }, // AC_M
    { AC, Low, 537, (2 + 1 + 1) }, // AC_L
    { Au, Multiple, 569, (2 + 1 + 1) }, // Au_M
    { Au, Single, 577, (2 + 1 + 1) }, // Au_S
    { Au, None, 573, (2 + 1 + 1) }, // Au_N
    { C, None, 499, (1 + 1 + 1) }, // C_N
    { C, Partial, 646, (1 + 1 + 1) }, // C_P
    { C, Complete, 614, (1 + 1 + 1) }, // C_C
    { I, None, 661, (1 + 1 + 1) }, // I_N
    { I, Partial, 664, (1 + 1 + 1) }, // I_P
    { I, Complete, 658, (1 + 1 + 1) }, // I_C
    { A, None, 640, (1 + 1 + 1) }, // A_N
    { A, Partial, 643, (1 + 1 + 1) }, // A_P
    { A, Complete, 637, (1 + 1 + 1) }, // A_C
    { E, Unproven, 655, (1 + 1 + 1) }, // E_U
    { E, ProofOfConcept, 483, (1 + 1 + 3) }, // E_POC
    { E, Functional, 649, (1 + 1 + 1) }, // E_F
    { E, High, 652, (1 + 1 + 1) }, // E_H
    { E, NotDefined, 593, (1 + 1 + 2) }, // E_ND
    { RL, OfficialFix, 518, (2 + 1 + 2) }, // RL_OF
    { RL, TemporaryFix, 523, (2 + 1 + 2) }, // RL_TF
    { RL, Workaround, 621, (2 + 1 + 1) }, // RL_W
    { RL, Unavailable, 617, (2 + 1 + 1) }, // RL_U
    { RL, NotDefined, 513, (2 + 1 + 2) }, // RL_ND
    { RC, Unconfirmed, 503, (2 + 1 + 2) }, // RC_UC
    { RC, Uncorroborated, 508, (2 + 1 + 2) }, // RC_UR
    { RC, Confirmed, 613, (2 + 1 + 1) }, // RC_C
    { RC, NotDefined, 498, (2 + 1 + 2) }, // RC_ND
    { CDP, None, 456, (3 + 1 + 1) }, // CDP_N
    { CDP, Low, 444, (3 + 1 + 1) }, // CDP_L
    { CDP, LowMedium, 444, (3 + 1 + 2) }, // CDP_LM
    { CDP, MediumHigh, 450, (3 + 1 + 2) }, // CDP_MH
    { CDP, High, 473, (3 + 1 + 1) }, // CDP_H
    { CDP, NotDefined, 456, (3 + 1 + 2) }, // CDP_ND
    { TD, None, 528, (2 + 1 + 1) }, // TD_N
    { TD, Low, 629, (2 + 1 + 1) }, // TD_L
    { TD, Medium, 633, (2 + 1 + 1) }, // TD_M
    { TD, High, 625, (2 + 1 + 1) }, // TD_H
    { TD, NotDefined, 528, (2 + 1 + 2) }, // TD_ND
    { CR, Low, 585, (2 + 1 + 1) }, // CR_L
    { CR, Medium, 589, (2 + 1 + 1) }, // CR_M
    { CR, High, 581, (2 + 1 + 1) }, // CR_H
    { CR, NotDefined, 478, (2 + 1 + 2) }, // CR_ND
    { IR, Low, 601, (2 + 1 + 1) }, // IR_L
    { IR, Medium, 605, (2 + 1 + 1) }, // IR_M
    { IR, High, 597, (2 + 1 + 1) }, // IR_H
    { IR, NotDefined, 488, (2 + 1 + 2) }, // IR_ND
    { AR, Low, 549, (2 + 1 + 1) }, // AR_L
    { AR, Medium, 553, (2 + 1 + 1) }, // AR_M
    { AR, High, 545, (2 + 1 + 1) }, // AR_H
    { AR, NotDefined, 468, (2 + 1 + 2) }, // AR_ND
}

// Single metric.
type Metric uint8

const (
  invalidMetric Metric = iota
    AV_N // AV:N (Access Vector: Network)
    AV_A // AV:A (Access Vector: AdjacentNetwork)
    AV_L // AV:L (Access Vector: Local)
    AC_H // AC:H (Access Complexity: High)
    AC_M // AC:M (Access Complexity: Medium)
    AC_L // AC:L (Access Complexity: Low)
    Au_M // Au:M (Authentication: Multiple)
    Au_S // Au:S (Authentication: Single)
    Au_N // Au:N (Authentication: None)
    C_N // C:N (Confidentiality Impact: None)
    C_P // C:P (Confidentiality Impact: Partial)
    C_C // C:C (Confidentiality Impact: Complete)
    I_N // I:N (Integrity Impact: None)
    I_P // I:P (Integrity Impact: Partial)
    I_C // I:C (Integrity Impact: Complete)
    A_N // A:N (Availability Impact: None)
    A_P // A:P (Availability Impact: Partial)
    A_C // A:C (Availability Impact: Complete)
    E_U // E:U (Exploitability: Unproven)
    E_POC // E:POC (Exploitability: ProofOfConcept)
    E_F // E:F (Exploitability: Functional)
    E_H // E:H (Exploitability: High)
    E_ND // E:ND (Exploitability: NotDefined)
    RL_OF // RL:OF (Remediation Level: OfficialFix)
    RL_TF // RL:TF (Remediation Level: TemporaryFix)
    RL_W // RL:W (Remediation Level: Workaround)
    RL_U // RL:U (Remediation Level: Unavailable)
    RL_ND // RL:ND (Remediation Level: NotDefined)
    RC_UC // RC:UC (Report Confidence: Unconfirmed)
    RC_UR // RC:UR (Report Confidence: Uncorroborated)
    RC_C // RC:C (Report Confidence: Confirmed)
    RC_ND // RC:ND (Report Confidence: NotDefined)
    CDP_N // CDP:N (Collateral Damage Potential: None)
    CDP_L // CDP:L (Collateral Damage Potential: Low)
    CDP_LM // CDP:LM (Collateral Damage Potential: LowMedium)
    CDP_MH // CDP:MH (Collateral Damage Potential: MediumHigh)
    CDP_H // CDP:H (Collateral Damage Potential: High)
    CDP_ND // CDP:ND (Collateral Damage Potential: NotDefined)
    TD_N // TD:N (Target Distribution: None)
    TD_L // TD:L (Target Distribution: Low)
    TD_M // TD:M (Target Distribution: Medium)
    TD_H // TD:H (Target Distribution: High)
    TD_ND // TD:ND (Target Distribution: NotDefined)
    CR_L // CR:L (Confidentiality Requirement: Low)
    CR_M // CR:M (Confidentiality Requirement: Medium)
    CR_H // CR:H (Confidentiality Requirement: High)
    CR_ND // CR:ND (Confidentiality Requirement: NotDefined)
    IR_L // IR:L (Integrity Requirement: Low)
    IR_M // IR:M (Integrity Requirement: Medium)
    IR_H // IR:H (Integrity Requirement: High)
    IR_ND // IR:ND (Integrity Requirement: NotDefined)
    AR_L // AR:L (Availability Requirement: Low)
    AR_M // AR:M (Availability Requirement: Medium)
    AR_H // AR:H (Availability Requirement: High)
    AR_ND // AR:ND (Availability Requirement: NotDefined)
  lastMetric
)

// Get metric key.
func (m Metric) Key() Key {
  if uint8(m) < uint8(lastMetric) {
    return metrics[uint8(m)].Key
  } else {
    return invalidKey
  }
}

// Get metric value.
func (m Metric) Value() Value {
  if uint8(m) < uint8(lastMetric) {
    return metrics[uint8(m)].Value
  } else {
    return invalidValue
  }
}

// Convert metric to string.
func (m Metric) String() string {
  if uint8(m) < uint8(lastMetric) {
    d := metrics[uint8(m)]
    return pack[d.strOfs:(d.strOfs + d.strLen)]
  } else {
    return ""
  }
}

// CVSS v2 vector.
//
// Vector metrics are packed into a single unsigned, 64-bit integer.
type Vector uint64

// Map of packed metric value to metric constant.  Used by Metrics()
// to unpack a packed vector.
var packedMetrics = [...]Metric {// AV
  invalidMetric,
  AV_N,
  AV_A,
  AV_L,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // AC
  invalidMetric,
  AC_H,
  AC_M,
  AC_L,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // Au
  invalidMetric,
  Au_M,
  Au_S,
  Au_N,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // C
  invalidMetric,
  C_N,
  C_P,
  C_C,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // I
  invalidMetric,
  I_N,
  I_P,
  I_C,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // A
  invalidMetric,
  A_N,
  A_P,
  A_C,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // E
  invalidMetric,
  E_U,
  E_POC,
  E_F,
  E_H,
  E_ND,
  invalidMetric,
  invalidMetric,
  // RL
  invalidMetric,
  RL_OF,
  RL_TF,
  RL_W,
  RL_U,
  RL_ND,
  invalidMetric,
  invalidMetric,
  // RC
  invalidMetric,
  RC_UC,
  RC_UR,
  RC_C,
  RC_ND,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // CDP
  invalidMetric,
  CDP_N,
  CDP_L,
  CDP_LM,
  CDP_MH,
  CDP_H,
  CDP_ND,
  invalidMetric,
  // TD
  invalidMetric,
  TD_N,
  TD_L,
  TD_M,
  TD_H,
  TD_ND,
  invalidMetric,
  invalidMetric,
  // CR
  invalidMetric,
  CR_L,
  CR_M,
  CR_H,
  CR_ND,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // IR
  invalidMetric,
  IR_L,
  IR_M,
  IR_H,
  IR_ND,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // AR
  invalidMetric,
  AR_L,
  AR_M,
  AR_H,
  AR_ND,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  }

// Return list of vector metrics.
func (v Vector) Metrics() []Metric {
  // allocate result
  r := make([]Metric, 0, 14)
  // AV
  if val := (uint64(v) >> 0) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(0 << 3) + val])
  }
  // AC
  if val := (uint64(v) >> 2) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(1 << 3) + val])
  }
  // Au
  if val := (uint64(v) >> 4) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(2 << 3) + val])
  }
  // C
  if val := (uint64(v) >> 6) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(3 << 3) + val])
  }
  // I
  if val := (uint64(v) >> 8) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(4 << 3) + val])
  }
  // A
  if val := (uint64(v) >> 10) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(5 << 3) + val])
  }
  // E
  if val := (uint64(v) >> 12) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(6 << 3) + val])
  }
  // RL
  if val := (uint64(v) >> 15) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(7 << 3) + val])
  }
  // RC
  if val := (uint64(v) >> 18) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(8 << 3) + val])
  }
  // CDP
  if val := (uint64(v) >> 21) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(9 << 3) + val])
  }
  // TD
  if val := (uint64(v) >> 24) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(10 << 3) + val])
  }
  // CR
  if val := (uint64(v) >> 27) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(11 << 3) + val])
  }
  // IR
  if val := (uint64(v) >> 30) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(12 << 3) + val])
  }
  // AR
  if val := (uint64(v) >> 33) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(13 << 3) + val])
  }

  // return result
  return r
}

// CVSS v2 vector prefix
const prefix = "CVSS:2"

// Return vector as string
func (v Vector) String() string {
  r := []string {  }

  for _, m := range(v.Metrics()) {
    r = append(r, m.String())
  }

  // build result
  return strings.Join(r, "/")
}

// map of metric string to shift, mask, and value
var metricStrs = map[string]struct {
  shift, mask uint8 // shift/mask
  val uint8 // encoded value
} {
    "AV:N": { 0, 2, 0 + 1 },
    "AV:A": { 0, 2, 1 + 1 },
    "AV:L": { 0, 2, 2 + 1 },
    "AC:H": { 2, 2, 0 + 1 },
    "AC:M": { 2, 2, 1 + 1 },
    "AC:L": { 2, 2, 2 + 1 },
    "Au:M": { 4, 2, 0 + 1 },
    "Au:S": { 4, 2, 1 + 1 },
    "Au:N": { 4, 2, 2 + 1 },
    "C:N": { 6, 2, 0 + 1 },
    "C:P": { 6, 2, 1 + 1 },
    "C:C": { 6, 2, 2 + 1 },
    "I:N": { 8, 2, 0 + 1 },
    "I:P": { 8, 2, 1 + 1 },
    "I:C": { 8, 2, 2 + 1 },
    "A:N": { 10, 2, 0 + 1 },
    "A:P": { 10, 2, 1 + 1 },
    "A:C": { 10, 2, 2 + 1 },
    "E:U": { 12, 3, 0 + 1 },
    "E:POC": { 12, 3, 1 + 1 },
    "E:F": { 12, 3, 2 + 1 },
    "E:H": { 12, 3, 3 + 1 },
    "E:ND": { 12, 3, 4 + 1 },
    "RL:OF": { 15, 3, 0 + 1 },
    "RL:TF": { 15, 3, 1 + 1 },
    "RL:W": { 15, 3, 2 + 1 },
    "RL:U": { 15, 3, 3 + 1 },
    "RL:ND": { 15, 3, 4 + 1 },
    "RC:UC": { 18, 3, 0 + 1 },
    "RC:UR": { 18, 3, 1 + 1 },
    "RC:C": { 18, 3, 2 + 1 },
    "RC:ND": { 18, 3, 3 + 1 },
    "CDP:N": { 21, 3, 0 + 1 },
    "CDP:L": { 21, 3, 1 + 1 },
    "CDP:LM": { 21, 3, 2 + 1 },
    "CDP:MH": { 21, 3, 3 + 1 },
    "CDP:H": { 21, 3, 4 + 1 },
    "CDP:ND": { 21, 3, 5 + 1 },
    "TD:N": { 24, 3, 0 + 1 },
    "TD:L": { 24, 3, 1 + 1 },
    "TD:M": { 24, 3, 2 + 1 },
    "TD:H": { 24, 3, 3 + 1 },
    "TD:ND": { 24, 3, 4 + 1 },
    "CR:L": { 27, 3, 0 + 1 },
    "CR:M": { 27, 3, 1 + 1 },
    "CR:H": { 27, 3, 2 + 1 },
    "CR:ND": { 27, 3, 3 + 1 },
    "IR:L": { 30, 3, 0 + 1 },
    "IR:M": { 30, 3, 1 + 1 },
    "IR:H": { 30, 3, 2 + 1 },
    "IR:ND": { 30, 3, 3 + 1 },
    "AR:L": { 33, 3, 0 + 1 },
    "AR:M": { 33, 3, 1 + 1 },
    "AR:H": { 33, 3, 2 + 1 },
    "AR:ND": { 33, 3, 3 + 1 },
}

// Parse string into CVSS v2 vector.
func ParseVector(s string) (Vector, error) {
  // split string into prefix and metrics
  parts := strings.Split(s, "/")
  if len(parts) < 2 {
    return Vector(0), fmt.Errorf("missing prefix: \"%s\"", s)
  }


  // v2 metrics have no prefix
  metricParts := parts


  // parse metrics, build result
  r := uint64(0)
  for _, ms := range(metricParts) {
    // parse metric string
    d, ok := metricStrs[ms]
    if !ok {
      return Vector(0), fmt.Errorf("unknown metric: \"%s\"", ms)
    }

    // check for duplicate metrics
    if (r & (((1 << uint64(d.mask)) - 1) << uint64(d.shift))) != 0 {
      return Vector(0), fmt.Errorf("duplicate metric: \"%s\"", ms)
    }

    // add to result
    r |= uint64(d.val) << uint64(d.shift) // set value
  }

  // return result
  return Vector(r), nil
}

// Parse string into CVSS v2 vector or panic on error.
func MustParseVector(s string) Vector {
  if v, err := ParseVector(s); err == nil {
    return v
  } else {
    panic(err)
  }
}

// Unmarshal vector from text.
func (v *Vector) UnmarshalText(b []byte) error {
  if nv, err := ParseVector(string(b)); err != nil {
    return err
  } else {
    *v = nv
    return nil
  }
}

// Marshal vector as JSON string.
func (v *Vector) MarshalJSON() ([]byte, error) {
  return json.Marshal(v.String())
}
