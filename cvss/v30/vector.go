

// CVSS v3.0 key, value, metrics, and vectors.
//
// Automatically generated by "cvss/gen-vector/gen.go".
package v30

import (
  "encoding/json"
  "fmt"
  "pmdn.org/nvd-go/cvss"
  "regexp"
  "strings"

)

// packed strings
const pack = "Modified Confidentiality ImpactModified Availability ImpactModified Privileges RequiredConfidentiality RequirementModified Attack ComplexityModified Integrity ImpactModified User InteractionAvailability RequirementModified Attack VectorExploit Code MaturityIntegrity RequirementRemediation LevelReport ConfidenceAdjacentNetworkModified ScopeProofOfConceptTemporaryFixOfficialFixUnavailableFunctionalNotDefinedReasonableWorkaroundConfirmedUnchangedPhysicalUnprovenChangedUnknownMediumLocalMAC:HMAC:LMAC:XMAV:AMAV:LMAV:NMAV:PMAV:XMPR:HMPR:LMPR:NMPR:XMUI:NMUI:RMUI:XAR:HAR:LAR:MAR:XCR:HCR:LCR:MCR:XHighIR:HIR:LIR:MIR:XMA:CMA:HMA:LMA:NMA:UMA:XMC:CMC:HMC:LMC:NMC:UMC:XMI:CMI:HMI:LMI:NMI:UMI:XMS:CMS:UMS:XNoneRC:CRC:RRC:URC:XRL:ORL:TRL:URL:WRL:XE:FE:HE:PE:UE:XLow"

// offset and length of packed Key strings
var keys = [...]struct {
  idOfs, idLen uint16 // id string offset and length
  nameOfs, nameLen uint16 // name string offset and length
} {
  { 0, 0, 0, 0 }, // invalidKey
  { 504, 2, 223, 13 },  // Attack Vector
  { 489, 2, 123, 17 },  // Attack Complexity
  { 529, 2, 68, 19 },  // Privileges Required
  { 549, 2, 174, 16 },  // User Interaction
  { 336, 1, 336, 5 },  // Scope
  { 9, 1, 9, 22 },  // Confidentiality Impact
  { 25, 1, 149, 16 },  // Integrity Impact
  { 40, 1, 40, 19 },  // Availability Impact
  { 236, 1, 236, 21 },  // Exploit Code Maturity
  { 719, 2, 278, 17 },  // Remediation Level
  { 703, 2, 295, 17 },  // Report Confidence
  { 579, 2, 87, 27 },  // Confidentiality Requirement
  { 599, 2, 257, 21 },  // Integrity Requirement
  { 563, 2, 190, 24 },  // Availability Requirement
  { 503, 3, 214, 22 },  // Modified Attack Vector
  { 488, 3, 114, 26 },  // Modified Attack Complexity
  { 528, 3, 59, 28 },  // Modified Privileges Required
  { 548, 3, 165, 25 },  // Modified User Interaction
  { 687, 2, 327, 14 },  // Modified Scope
  { 590, 2, 0, 31 },  // Modified Confidentiality Impact
  { 610, 2, 140, 25 },  // Modified Integrity Impact
  { 488, 2, 31, 28 },  // Modified Availability Impact
}

// Metric key.
type Key uint8
const (
  invalidKey Key = iota
  AV // Attack Vector
  AC // Attack Complexity
  PR // Privileges Required
  UI // User Interaction
  S // Scope
  C // Confidentiality Impact
  I // Integrity Impact
  A // Availability Impact
  E // Exploit Code Maturity
  RL // Remediation Level
  RC // Report Confidence
  CR // Confidentiality Requirement
  IR // Integrity Requirement
  AR // Availability Requirement
  MAV // Modified Attack Vector
  MAC // Modified Attack Complexity
  MPR // Modified Privileges Required
  MUI // Modified User Interaction
  MS // Modified Scope
  MC // Modified Confidentiality Impact
  MI // Modified Integrity Impact
  MA // Modified Availability Impact
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
  { 40, 1, 312, 15 }, // AdjacentNetwork
  { 9, 1, 463, 7 }, // Changed
  { 9, 1, 429, 9 }, // Confirmed
  { 364, 1, 389, 10 }, // Functional
  { 492, 1, 595, 4 }, // High
  { 290, 1, 483, 5 }, // Local
  { 290, 1, 754, 3 }, // Low
  { 0, 1, 477, 6 }, // Medium
  { 320, 1, 320, 7 }, // Network
  { 320, 1, 699, 4 }, // None
  { 502, 1, 399, 10 }, // NotDefined
  { 346, 1, 367, 11 }, // OfficialFix
  { 68, 1, 447, 8 }, // Physical
  { 68, 1, 341, 14 }, // ProofOfConcept
  { 79, 1, 409, 10 }, // Reasonable
  { 79, 1, 79, 8 }, // Required
  { 355, 1, 355, 12 }, // TemporaryFix
  { 174, 1, 378, 11 }, // Unavailable
  { 174, 1, 438, 9 }, // Unchanged
  { 174, 1, 470, 7 }, // Unknown
  { 174, 1, 455, 8 }, // Unproven
  { 419, 1, 419, 10 }, // Workaround
}

// Metric value.
type Value uint8
const (
  invalidValue Value = iota
  AdjacentNetwork // A
  Changed // C
  Confirmed // C
  Functional // F
  High // H
  Local // L
  Low // L
  Medium // M
  Network // N
  None // N
  NotDefined // X
  OfficialFix // O
  Physical // P
  ProofOfConcept // P
  Reasonable // R
  Required // R
  TemporaryFix // T
  Unavailable // U
  Unchanged // U
  Unknown // U
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
    { AV, Network, 514, (2 + 1 + 1) }, // AV_N
    { AV, AdjacentNetwork, 504, (2 + 1 + 1) }, // AV_A
    { AV, Local, 509, (2 + 1 + 1) }, // AV_L
    { AV, Physical, 519, (2 + 1 + 1) }, // AV_P
    { AC, High, 489, (2 + 1 + 1) }, // AC_H
    { AC, Low, 494, (2 + 1 + 1) }, // AC_L
    { PR, High, 529, (2 + 1 + 1) }, // PR_H
    { PR, Low, 534, (2 + 1 + 1) }, // PR_L
    { PR, None, 539, (2 + 1 + 1) }, // PR_N
    { UI, None, 549, (2 + 1 + 1) }, // UI_N
    { UI, Required, 554, (2 + 1 + 1) }, // UI_R
    { S, Unchanged, 692, (1 + 1 + 1) }, // S_U
    { S, Changed, 688, (1 + 1 + 1) }, // S_C
    { C, None, 652, (1 + 1 + 1) }, // C_N
    { C, Low, 495, (1 + 1 + 1) }, // C_L
    { C, High, 490, (1 + 1 + 1) }, // C_H
    { I, None, 550, (1 + 1 + 1) }, // I_N
    { I, Low, 672, (1 + 1 + 1) }, // I_L
    { I, High, 668, (1 + 1 + 1) }, // I_H
    { A, None, 628, (1 + 1 + 1) }, // A_N
    { A, Low, 624, (1 + 1 + 1) }, // A_L
    { A, High, 620, (1 + 1 + 1) }, // A_H
    { E, Unproven, 748, (1 + 1 + 1) }, // E_U
    { E, ProofOfConcept, 745, (1 + 1 + 1) }, // E_P
    { E, Functional, 739, (1 + 1 + 1) }, // E_F
    { E, High, 742, (1 + 1 + 1) }, // E_H
    { E, NotDefined, 751, (1 + 1 + 1) }, // E_X
    { RL, OfficialFix, 719, (2 + 1 + 1) }, // RL_O
    { RL, TemporaryFix, 723, (2 + 1 + 1) }, // RL_T
    { RL, Workaround, 731, (2 + 1 + 1) }, // RL_W
    { RL, Unavailable, 727, (2 + 1 + 1) }, // RL_U
    { RL, NotDefined, 735, (2 + 1 + 1) }, // RL_X
    { RC, Unknown, 711, (2 + 1 + 1) }, // RC_U
    { RC, Reasonable, 707, (2 + 1 + 1) }, // RC_R
    { RC, Confirmed, 703, (2 + 1 + 1) }, // RC_C
    { RC, NotDefined, 715, (2 + 1 + 1) }, // RC_X
    { CR, Low, 583, (2 + 1 + 1) }, // CR_L
    { CR, Medium, 587, (2 + 1 + 1) }, // CR_M
    { CR, High, 579, (2 + 1 + 1) }, // CR_H
    { CR, NotDefined, 591, (2 + 1 + 1) }, // CR_X
    { IR, Low, 603, (2 + 1 + 1) }, // IR_L
    { IR, Medium, 607, (2 + 1 + 1) }, // IR_M
    { IR, High, 599, (2 + 1 + 1) }, // IR_H
    { IR, NotDefined, 611, (2 + 1 + 1) }, // IR_X
    { AR, Low, 567, (2 + 1 + 1) }, // AR_L
    { AR, Medium, 571, (2 + 1 + 1) }, // AR_M
    { AR, High, 563, (2 + 1 + 1) }, // AR_H
    { AR, NotDefined, 575, (2 + 1 + 1) }, // AR_X
    { MAV, Network, 513, (3 + 1 + 1) }, // MAV_N
    { MAV, AdjacentNetwork, 503, (3 + 1 + 1) }, // MAV_A
    { MAV, Local, 508, (3 + 1 + 1) }, // MAV_L
    { MAV, Physical, 518, (3 + 1 + 1) }, // MAV_P
    { MAV, NotDefined, 523, (3 + 1 + 1) }, // MAV_X
    { MAC, High, 488, (3 + 1 + 1) }, // MAC_H
    { MAC, Low, 493, (3 + 1 + 1) }, // MAC_L
    { MAC, NotDefined, 498, (3 + 1 + 1) }, // MAC_X
    { MPR, High, 528, (3 + 1 + 1) }, // MPR_H
    { MPR, Low, 533, (3 + 1 + 1) }, // MPR_L
    { MPR, None, 538, (3 + 1 + 1) }, // MPR_N
    { MPR, NotDefined, 543, (3 + 1 + 1) }, // MPR_X
    { MUI, None, 548, (3 + 1 + 1) }, // MUI_N
    { MUI, Required, 553, (3 + 1 + 1) }, // MUI_R
    { MUI, NotDefined, 558, (3 + 1 + 1) }, // MUI_X
    { MS, Unchanged, 691, (2 + 1 + 1) }, // MS_U
    { MS, Changed, 687, (2 + 1 + 1) }, // MS_C
    { MS, NotDefined, 695, (2 + 1 + 1) }, // MS_X
    { MC, Unchanged, 655, (2 + 1 + 1) }, // MC_U
    { MC, Changed, 639, (2 + 1 + 1) }, // MC_C
    { MC, None, 651, (2 + 1 + 1) }, // MC_N
    { MC, Low, 647, (2 + 1 + 1) }, // MC_L
    { MC, High, 643, (2 + 1 + 1) }, // MC_H
    { MC, NotDefined, 659, (2 + 1 + 1) }, // MC_X
    { MI, Unchanged, 679, (2 + 1 + 1) }, // MI_U
    { MI, Changed, 663, (2 + 1 + 1) }, // MI_C
    { MI, None, 675, (2 + 1 + 1) }, // MI_N
    { MI, Low, 671, (2 + 1 + 1) }, // MI_L
    { MI, High, 667, (2 + 1 + 1) }, // MI_H
    { MI, NotDefined, 683, (2 + 1 + 1) }, // MI_X
    { MA, Unchanged, 631, (2 + 1 + 1) }, // MA_U
    { MA, Changed, 615, (2 + 1 + 1) }, // MA_C
    { MA, None, 627, (2 + 1 + 1) }, // MA_N
    { MA, Low, 623, (2 + 1 + 1) }, // MA_L
    { MA, High, 619, (2 + 1 + 1) }, // MA_H
    { MA, NotDefined, 635, (2 + 1 + 1) }, // MA_X
}

// Single metric.
type Metric uint8

const (
  invalidMetric Metric = iota
    AV_N // AV:N (Attack Vector: Network)
    AV_A // AV:A (Attack Vector: AdjacentNetwork)
    AV_L // AV:L (Attack Vector: Local)
    AV_P // AV:P (Attack Vector: Physical)
    AC_H // AC:H (Attack Complexity: High)
    AC_L // AC:L (Attack Complexity: Low)
    PR_H // PR:H (Privileges Required: High)
    PR_L // PR:L (Privileges Required: Low)
    PR_N // PR:N (Privileges Required: None)
    UI_N // UI:N (User Interaction: None)
    UI_R // UI:R (User Interaction: Required)
    S_U // S:U (Scope: Unchanged)
    S_C // S:C (Scope: Changed)
    C_N // C:N (Confidentiality Impact: None)
    C_L // C:L (Confidentiality Impact: Low)
    C_H // C:H (Confidentiality Impact: High)
    I_N // I:N (Integrity Impact: None)
    I_L // I:L (Integrity Impact: Low)
    I_H // I:H (Integrity Impact: High)
    A_N // A:N (Availability Impact: None)
    A_L // A:L (Availability Impact: Low)
    A_H // A:H (Availability Impact: High)
    E_U // E:U (Exploit Code Maturity: Unproven)
    E_P // E:P (Exploit Code Maturity: ProofOfConcept)
    E_F // E:F (Exploit Code Maturity: Functional)
    E_H // E:H (Exploit Code Maturity: High)
    E_X // E:X (Exploit Code Maturity: NotDefined)
    RL_O // RL:O (Remediation Level: OfficialFix)
    RL_T // RL:T (Remediation Level: TemporaryFix)
    RL_W // RL:W (Remediation Level: Workaround)
    RL_U // RL:U (Remediation Level: Unavailable)
    RL_X // RL:X (Remediation Level: NotDefined)
    RC_U // RC:U (Report Confidence: Unknown)
    RC_R // RC:R (Report Confidence: Reasonable)
    RC_C // RC:C (Report Confidence: Confirmed)
    RC_X // RC:X (Report Confidence: NotDefined)
    CR_L // CR:L (Confidentiality Requirement: Low)
    CR_M // CR:M (Confidentiality Requirement: Medium)
    CR_H // CR:H (Confidentiality Requirement: High)
    CR_X // CR:X (Confidentiality Requirement: NotDefined)
    IR_L // IR:L (Integrity Requirement: Low)
    IR_M // IR:M (Integrity Requirement: Medium)
    IR_H // IR:H (Integrity Requirement: High)
    IR_X // IR:X (Integrity Requirement: NotDefined)
    AR_L // AR:L (Availability Requirement: Low)
    AR_M // AR:M (Availability Requirement: Medium)
    AR_H // AR:H (Availability Requirement: High)
    AR_X // AR:X (Availability Requirement: NotDefined)
    MAV_N // MAV:N (Modified Attack Vector: Network)
    MAV_A // MAV:A (Modified Attack Vector: AdjacentNetwork)
    MAV_L // MAV:L (Modified Attack Vector: Local)
    MAV_P // MAV:P (Modified Attack Vector: Physical)
    MAV_X // MAV:X (Modified Attack Vector: NotDefined)
    MAC_H // MAC:H (Modified Attack Complexity: High)
    MAC_L // MAC:L (Modified Attack Complexity: Low)
    MAC_X // MAC:X (Modified Attack Complexity: NotDefined)
    MPR_H // MPR:H (Modified Privileges Required: High)
    MPR_L // MPR:L (Modified Privileges Required: Low)
    MPR_N // MPR:N (Modified Privileges Required: None)
    MPR_X // MPR:X (Modified Privileges Required: NotDefined)
    MUI_N // MUI:N (Modified User Interaction: None)
    MUI_R // MUI:R (Modified User Interaction: Required)
    MUI_X // MUI:X (Modified User Interaction: NotDefined)
    MS_U // MS:U (Modified Scope: Unchanged)
    MS_C // MS:C (Modified Scope: Changed)
    MS_X // MS:X (Modified Scope: NotDefined)
    MC_U // MC:U (Modified Confidentiality Impact: Unchanged)
    MC_C // MC:C (Modified Confidentiality Impact: Changed)
    MC_N // MC:N (Modified Confidentiality Impact: None)
    MC_L // MC:L (Modified Confidentiality Impact: Low)
    MC_H // MC:H (Modified Confidentiality Impact: High)
    MC_X // MC:X (Modified Confidentiality Impact: NotDefined)
    MI_U // MI:U (Modified Integrity Impact: Unchanged)
    MI_C // MI:C (Modified Integrity Impact: Changed)
    MI_N // MI:N (Modified Integrity Impact: None)
    MI_L // MI:L (Modified Integrity Impact: Low)
    MI_H // MI:H (Modified Integrity Impact: High)
    MI_X // MI:X (Modified Integrity Impact: NotDefined)
    MA_U // MA:U (Modified Availability Impact: Unchanged)
    MA_C // MA:C (Modified Availability Impact: Changed)
    MA_N // MA:N (Modified Availability Impact: None)
    MA_L // MA:L (Modified Availability Impact: Low)
    MA_H // MA:H (Modified Availability Impact: High)
    MA_X // MA:X (Modified Availability Impact: NotDefined)
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

// CVSS v3.0 vector.
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
  AV_P,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // AC
  invalidMetric,
  AC_H,
  AC_L,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // PR
  invalidMetric,
  PR_H,
  PR_L,
  PR_N,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // UI
  invalidMetric,
  UI_N,
  UI_R,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // S
  invalidMetric,
  S_U,
  S_C,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // C
  invalidMetric,
  C_N,
  C_L,
  C_H,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // I
  invalidMetric,
  I_N,
  I_L,
  I_H,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // A
  invalidMetric,
  A_N,
  A_L,
  A_H,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // E
  invalidMetric,
  E_U,
  E_P,
  E_F,
  E_H,
  E_X,
  invalidMetric,
  invalidMetric,
  // RL
  invalidMetric,
  RL_O,
  RL_T,
  RL_W,
  RL_U,
  RL_X,
  invalidMetric,
  invalidMetric,
  // RC
  invalidMetric,
  RC_U,
  RC_R,
  RC_C,
  RC_X,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // CR
  invalidMetric,
  CR_L,
  CR_M,
  CR_H,
  CR_X,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // IR
  invalidMetric,
  IR_L,
  IR_M,
  IR_H,
  IR_X,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // AR
  invalidMetric,
  AR_L,
  AR_M,
  AR_H,
  AR_X,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // MAV
  invalidMetric,
  MAV_N,
  MAV_A,
  MAV_L,
  MAV_P,
  MAV_X,
  invalidMetric,
  invalidMetric,
  // MAC
  invalidMetric,
  MAC_H,
  MAC_L,
  MAC_X,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // MPR
  invalidMetric,
  MPR_H,
  MPR_L,
  MPR_N,
  MPR_X,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // MUI
  invalidMetric,
  MUI_N,
  MUI_R,
  MUI_X,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // MS
  invalidMetric,
  MS_U,
  MS_C,
  MS_X,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  invalidMetric,
  // MC
  invalidMetric,
  MC_U,
  MC_C,
  MC_N,
  MC_L,
  MC_H,
  MC_X,
  invalidMetric,
  // MI
  invalidMetric,
  MI_U,
  MI_C,
  MI_N,
  MI_L,
  MI_H,
  MI_X,
  invalidMetric,
  // MA
  invalidMetric,
  MA_U,
  MA_C,
  MA_N,
  MA_L,
  MA_H,
  MA_X,
  invalidMetric,
  }

// Return list of vector metrics.
func (v Vector) Metrics() []Metric {
  // allocate result
  r := make([]Metric, 0, 22)
  // AV
  if val := (uint64(v) >> 0) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(0 << 3) + val])
  }
  // AC
  if val := (uint64(v) >> 3) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(1 << 3) + val])
  }
  // PR
  if val := (uint64(v) >> 5) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(2 << 3) + val])
  }
  // UI
  if val := (uint64(v) >> 7) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(3 << 3) + val])
  }
  // S
  if val := (uint64(v) >> 9) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(4 << 3) + val])
  }
  // C
  if val := (uint64(v) >> 11) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(5 << 3) + val])
  }
  // I
  if val := (uint64(v) >> 13) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(6 << 3) + val])
  }
  // A
  if val := (uint64(v) >> 15) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(7 << 3) + val])
  }
  // E
  if val := (uint64(v) >> 17) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(8 << 3) + val])
  }
  // RL
  if val := (uint64(v) >> 20) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(9 << 3) + val])
  }
  // RC
  if val := (uint64(v) >> 23) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(10 << 3) + val])
  }
  // CR
  if val := (uint64(v) >> 26) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(11 << 3) + val])
  }
  // IR
  if val := (uint64(v) >> 29) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(12 << 3) + val])
  }
  // AR
  if val := (uint64(v) >> 32) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(13 << 3) + val])
  }
  // MAV
  if val := (uint64(v) >> 35) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(14 << 3) + val])
  }
  // MAC
  if val := (uint64(v) >> 38) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(15 << 3) + val])
  }
  // MPR
  if val := (uint64(v) >> 40) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(16 << 3) + val])
  }
  // MUI
  if val := (uint64(v) >> 43) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(17 << 3) + val])
  }
  // MS
  if val := (uint64(v) >> 45) & ((1 << 2) - 1); val > 0 {
    r = append(r, packedMetrics[(18 << 3) + val])
  }
  // MC
  if val := (uint64(v) >> 47) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(19 << 3) + val])
  }
  // MI
  if val := (uint64(v) >> 50) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(20 << 3) + val])
  }
  // MA
  if val := (uint64(v) >> 53) & ((1 << 3) - 1); val > 0 {
    r = append(r, packedMetrics[(21 << 3) + val])
  }

  // return result
  return r
}

// CVSS v3.0 vector prefix
const prefix = "CVSS:3.0"

// Return vector as string
func (v Vector) String() string {
  r := []string { prefix }

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
    "AV:N": { 0, 3, 0 + 1 },
    "AV:A": { 0, 3, 1 + 1 },
    "AV:L": { 0, 3, 2 + 1 },
    "AV:P": { 0, 3, 3 + 1 },
    "AC:H": { 3, 2, 0 + 1 },
    "AC:L": { 3, 2, 1 + 1 },
    "PR:H": { 5, 2, 0 + 1 },
    "PR:L": { 5, 2, 1 + 1 },
    "PR:N": { 5, 2, 2 + 1 },
    "UI:N": { 7, 2, 0 + 1 },
    "UI:R": { 7, 2, 1 + 1 },
    "S:U": { 9, 2, 0 + 1 },
    "S:C": { 9, 2, 1 + 1 },
    "C:N": { 11, 2, 0 + 1 },
    "C:L": { 11, 2, 1 + 1 },
    "C:H": { 11, 2, 2 + 1 },
    "I:N": { 13, 2, 0 + 1 },
    "I:L": { 13, 2, 1 + 1 },
    "I:H": { 13, 2, 2 + 1 },
    "A:N": { 15, 2, 0 + 1 },
    "A:L": { 15, 2, 1 + 1 },
    "A:H": { 15, 2, 2 + 1 },
    "E:U": { 17, 3, 0 + 1 },
    "E:P": { 17, 3, 1 + 1 },
    "E:F": { 17, 3, 2 + 1 },
    "E:H": { 17, 3, 3 + 1 },
    "E:X": { 17, 3, 4 + 1 },
    "RL:O": { 20, 3, 0 + 1 },
    "RL:T": { 20, 3, 1 + 1 },
    "RL:W": { 20, 3, 2 + 1 },
    "RL:U": { 20, 3, 3 + 1 },
    "RL:X": { 20, 3, 4 + 1 },
    "RC:U": { 23, 3, 0 + 1 },
    "RC:R": { 23, 3, 1 + 1 },
    "RC:C": { 23, 3, 2 + 1 },
    "RC:X": { 23, 3, 3 + 1 },
    "CR:L": { 26, 3, 0 + 1 },
    "CR:M": { 26, 3, 1 + 1 },
    "CR:H": { 26, 3, 2 + 1 },
    "CR:X": { 26, 3, 3 + 1 },
    "IR:L": { 29, 3, 0 + 1 },
    "IR:M": { 29, 3, 1 + 1 },
    "IR:H": { 29, 3, 2 + 1 },
    "IR:X": { 29, 3, 3 + 1 },
    "AR:L": { 32, 3, 0 + 1 },
    "AR:M": { 32, 3, 1 + 1 },
    "AR:H": { 32, 3, 2 + 1 },
    "AR:X": { 32, 3, 3 + 1 },
    "MAV:N": { 35, 3, 0 + 1 },
    "MAV:A": { 35, 3, 1 + 1 },
    "MAV:L": { 35, 3, 2 + 1 },
    "MAV:P": { 35, 3, 3 + 1 },
    "MAV:X": { 35, 3, 4 + 1 },
    "MAC:H": { 38, 2, 0 + 1 },
    "MAC:L": { 38, 2, 1 + 1 },
    "MAC:X": { 38, 2, 2 + 1 },
    "MPR:H": { 40, 3, 0 + 1 },
    "MPR:L": { 40, 3, 1 + 1 },
    "MPR:N": { 40, 3, 2 + 1 },
    "MPR:X": { 40, 3, 3 + 1 },
    "MUI:N": { 43, 2, 0 + 1 },
    "MUI:R": { 43, 2, 1 + 1 },
    "MUI:X": { 43, 2, 2 + 1 },
    "MS:U": { 45, 2, 0 + 1 },
    "MS:C": { 45, 2, 1 + 1 },
    "MS:X": { 45, 2, 2 + 1 },
    "MC:U": { 47, 3, 0 + 1 },
    "MC:C": { 47, 3, 1 + 1 },
    "MC:N": { 47, 3, 2 + 1 },
    "MC:L": { 47, 3, 3 + 1 },
    "MC:H": { 47, 3, 4 + 1 },
    "MC:X": { 47, 3, 5 + 1 },
    "MI:U": { 50, 3, 0 + 1 },
    "MI:C": { 50, 3, 1 + 1 },
    "MI:N": { 50, 3, 2 + 1 },
    "MI:L": { 50, 3, 3 + 1 },
    "MI:H": { 50, 3, 4 + 1 },
    "MI:X": { 50, 3, 5 + 1 },
    "MA:U": { 53, 3, 0 + 1 },
    "MA:C": { 53, 3, 1 + 1 },
    "MA:N": { 53, 3, 2 + 1 },
    "MA:L": { 53, 3, 3 + 1 },
    "MA:H": { 53, 3, 4 + 1 },
    "MA:X": { 53, 3, 5 + 1 },
}

// Parse string into CVSS v3.0 vector.
func ParseVector(s string) (Vector, error) {
  // split string into prefix and metrics
  parts := strings.Split(s, "/")
  if len(parts) < 2 {
    return Vector(0), fmt.Errorf("missing prefix: \"%s\"", s)
  }


  // check prefix
  if parts[0] != prefix {
    return Vector(0), fmt.Errorf("invalid prefix: \"%s\"", parts[0])
  }

  // skip prefix
  metricParts := parts[1:]

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

// Parse string into CVSS v3.0 vector or panic on error.
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

// Get vector version.
func (v Vector) Version() cvss.Version {
  return cvss.V30
}

// vector string regex (from JSON schema)
var matchPattern = regexp.MustCompile("^CVSS:3[.]0/((AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$")

// Returns true if the given string is a valid CVSS v3.0 string.
func ValidVectorString(s string) bool {
  return matchPattern.MatchString(s)
}
