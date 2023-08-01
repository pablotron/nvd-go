
// Enumerated string types.
//
// Automatically generated by `gen-enums.rb`.
package v31

import "fmt"

// packed string of enumeration values
const _pack_ba6499cc006baa2f8f13f074011ebfd1 = `ADJACENT_NETWORKPROOF_OF_CONCEPTTEMPORARY_FIXOFFICIAL_FIXNOT_DEFINEDUNAVAILABLEFUNCTIONALWORKAROUNDREASONABLEUNCHANGEDCONFIRMEDPHYSICALREQUIREDUNPROVENCRITICALUNKNOWNMEDIUMLOCALHIGHNONELOW`


// Attack Vector
type AttackVector uint8

const (
  InvalidAttackVector AttackVector = iota
  AVNetwork
  AVAdjacentNetwork
  AVLocal
  AVPhysical
)

// Convert AttackVector to string.
func (v AttackVector) String() string {
  switch v {
  case AVNetwork:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[9:16]
  case AVAdjacentNetwork:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[0:16]
  case AVLocal:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[172:177]
  case AVPhysical:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[127:135]
  default:
    return ""
  }
}

// Unmarshal AttackVector from text.
func (v *AttackVector) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "NETWORK":
    *v = AVNetwork
    return nil
  case "ADJACENT_NETWORK":
    *v = AVAdjacentNetwork
    return nil
  case "LOCAL":
    *v = AVLocal
    return nil
  case "PHYSICAL":
    *v = AVPhysical
    return nil
  default:
    return fmt.Errorf("invalid AttackVector: \"%s\"", s)
  }
}

// Marshal AttackVector to text.
func (v *AttackVector) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Modified Attack Vector
type ModifiedAttackVector uint8

const (
  InvalidModifiedAttackVector ModifiedAttackVector = iota
  MAVNetwork
  MAVAdjacentNetwork
  MAVLocal
  MAVPhysical
  MAVNotDefined
)

// Convert ModifiedAttackVector to string.
func (v ModifiedAttackVector) String() string {
  switch v {
  case MAVNetwork:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[9:16]
  case MAVAdjacentNetwork:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[0:16]
  case MAVLocal:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[172:177]
  case MAVPhysical:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[127:135]
  case MAVNotDefined:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[57:68]
  default:
    return ""
  }
}

// Unmarshal ModifiedAttackVector from text.
func (v *ModifiedAttackVector) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "NETWORK":
    *v = MAVNetwork
    return nil
  case "ADJACENT_NETWORK":
    *v = MAVAdjacentNetwork
    return nil
  case "LOCAL":
    *v = MAVLocal
    return nil
  case "PHYSICAL":
    *v = MAVPhysical
    return nil
  case "NOT_DEFINED":
    *v = MAVNotDefined
    return nil
  default:
    return fmt.Errorf("invalid ModifiedAttackVector: \"%s\"", s)
  }
}

// Marshal ModifiedAttackVector to text.
func (v *ModifiedAttackVector) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Attack Complexity
type AttackComplexity uint8

const (
  InvalidAttackComplexity AttackComplexity = iota
  ACHigh
  ACLow
)

// Convert AttackComplexity to string.
func (v AttackComplexity) String() string {
  switch v {
  case ACHigh:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[177:181]
  case ACLow:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[185:188]
  default:
    return ""
  }
}

// Unmarshal AttackComplexity from text.
func (v *AttackComplexity) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "HIGH":
    *v = ACHigh
    return nil
  case "LOW":
    *v = ACLow
    return nil
  default:
    return fmt.Errorf("invalid AttackComplexity: \"%s\"", s)
  }
}

// Marshal AttackComplexity to text.
func (v *AttackComplexity) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Modified Attack Complexity
type ModifiedAttackComplexity uint8

const (
  InvalidModifiedAttackComplexity ModifiedAttackComplexity = iota
  MACHigh
  MACLow
  MACNotDefined
)

// Convert ModifiedAttackComplexity to string.
func (v ModifiedAttackComplexity) String() string {
  switch v {
  case MACHigh:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[177:181]
  case MACLow:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[185:188]
  case MACNotDefined:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[57:68]
  default:
    return ""
  }
}

// Unmarshal ModifiedAttackComplexity from text.
func (v *ModifiedAttackComplexity) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "HIGH":
    *v = MACHigh
    return nil
  case "LOW":
    *v = MACLow
    return nil
  case "NOT_DEFINED":
    *v = MACNotDefined
    return nil
  default:
    return fmt.Errorf("invalid ModifiedAttackComplexity: \"%s\"", s)
  }
}

// Marshal ModifiedAttackComplexity to text.
func (v *ModifiedAttackComplexity) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Privileges Required
type PrivilegesRequired uint8

const (
  InvalidPrivilegesRequired PrivilegesRequired = iota
  PRHigh
  PRLow
  PRNone
)

// Convert PrivilegesRequired to string.
func (v PrivilegesRequired) String() string {
  switch v {
  case PRHigh:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[177:181]
  case PRLow:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[185:188]
  case PRNone:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[181:185]
  default:
    return ""
  }
}

// Unmarshal PrivilegesRequired from text.
func (v *PrivilegesRequired) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "HIGH":
    *v = PRHigh
    return nil
  case "LOW":
    *v = PRLow
    return nil
  case "NONE":
    *v = PRNone
    return nil
  default:
    return fmt.Errorf("invalid PrivilegesRequired: \"%s\"", s)
  }
}

// Marshal PrivilegesRequired to text.
func (v *PrivilegesRequired) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Modified Privileges Required
type ModifiedPrivilegesRequired uint8

const (
  InvalidModifiedPrivilegesRequired ModifiedPrivilegesRequired = iota
  MPRHigh
  MPRLow
  MPRNone
  MPRNotDefined
)

// Convert ModifiedPrivilegesRequired to string.
func (v ModifiedPrivilegesRequired) String() string {
  switch v {
  case MPRHigh:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[177:181]
  case MPRLow:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[185:188]
  case MPRNone:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[181:185]
  case MPRNotDefined:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[57:68]
  default:
    return ""
  }
}

// Unmarshal ModifiedPrivilegesRequired from text.
func (v *ModifiedPrivilegesRequired) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "HIGH":
    *v = MPRHigh
    return nil
  case "LOW":
    *v = MPRLow
    return nil
  case "NONE":
    *v = MPRNone
    return nil
  case "NOT_DEFINED":
    *v = MPRNotDefined
    return nil
  default:
    return fmt.Errorf("invalid ModifiedPrivilegesRequired: \"%s\"", s)
  }
}

// Marshal ModifiedPrivilegesRequired to text.
func (v *ModifiedPrivilegesRequired) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// User Interaction
type UserInteraction uint8

const (
  InvalidUserInteraction UserInteraction = iota
  UINone
  UIRequired
)

// Convert UserInteraction to string.
func (v UserInteraction) String() string {
  switch v {
  case UINone:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[181:185]
  case UIRequired:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[135:143]
  default:
    return ""
  }
}

// Unmarshal UserInteraction from text.
func (v *UserInteraction) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "NONE":
    *v = UINone
    return nil
  case "REQUIRED":
    *v = UIRequired
    return nil
  default:
    return fmt.Errorf("invalid UserInteraction: \"%s\"", s)
  }
}

// Marshal UserInteraction to text.
func (v *UserInteraction) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Modified User Interaction
type ModifiedUserInteraction uint8

const (
  InvalidModifiedUserInteraction ModifiedUserInteraction = iota
  MUINone
  MUIRequired
  MUINotDefined
)

// Convert ModifiedUserInteraction to string.
func (v ModifiedUserInteraction) String() string {
  switch v {
  case MUINone:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[181:185]
  case MUIRequired:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[135:143]
  case MUINotDefined:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[57:68]
  default:
    return ""
  }
}

// Unmarshal ModifiedUserInteraction from text.
func (v *ModifiedUserInteraction) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "NONE":
    *v = MUINone
    return nil
  case "REQUIRED":
    *v = MUIRequired
    return nil
  case "NOT_DEFINED":
    *v = MUINotDefined
    return nil
  default:
    return fmt.Errorf("invalid ModifiedUserInteraction: \"%s\"", s)
  }
}

// Marshal ModifiedUserInteraction to text.
func (v *ModifiedUserInteraction) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Scope
type Scope uint8

const (
  InvalidScope Scope = iota
  SUnchanged
  SChanged
)

// Convert Scope to string.
func (v Scope) String() string {
  switch v {
  case SUnchanged:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[109:118]
  case SChanged:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[111:118]
  default:
    return ""
  }
}

// Unmarshal Scope from text.
func (v *Scope) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "UNCHANGED":
    *v = SUnchanged
    return nil
  case "CHANGED":
    *v = SChanged
    return nil
  default:
    return fmt.Errorf("invalid Scope: \"%s\"", s)
  }
}

// Marshal Scope to text.
func (v *Scope) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Modified Scope
type ModifiedScope uint8

const (
  InvalidModifiedScope ModifiedScope = iota
  MSUnchanged
  MSChanged
  MSNotDefined
)

// Convert ModifiedScope to string.
func (v ModifiedScope) String() string {
  switch v {
  case MSUnchanged:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[109:118]
  case MSChanged:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[111:118]
  case MSNotDefined:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[57:68]
  default:
    return ""
  }
}

// Unmarshal ModifiedScope from text.
func (v *ModifiedScope) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "UNCHANGED":
    *v = MSUnchanged
    return nil
  case "CHANGED":
    *v = MSChanged
    return nil
  case "NOT_DEFINED":
    *v = MSNotDefined
    return nil
  default:
    return fmt.Errorf("invalid ModifiedScope: \"%s\"", s)
  }
}

// Marshal ModifiedScope to text.
func (v *ModifiedScope) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Cia
type Cia uint8

const (
  InvalidCia Cia = iota
  CNone
  CLow
  CHigh
)

// Convert Cia to string.
func (v Cia) String() string {
  switch v {
  case CNone:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[181:185]
  case CLow:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[185:188]
  case CHigh:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[177:181]
  default:
    return ""
  }
}

// Unmarshal Cia from text.
func (v *Cia) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "NONE":
    *v = CNone
    return nil
  case "LOW":
    *v = CLow
    return nil
  case "HIGH":
    *v = CHigh
    return nil
  default:
    return fmt.Errorf("invalid Cia: \"%s\"", s)
  }
}

// Marshal Cia to text.
func (v *Cia) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Modified Cia
type ModifiedCia uint8

const (
  InvalidModifiedCia ModifiedCia = iota
  MCNone
  MCLow
  MCHigh
  MCNotDefined
)

// Convert ModifiedCia to string.
func (v ModifiedCia) String() string {
  switch v {
  case MCNone:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[181:185]
  case MCLow:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[185:188]
  case MCHigh:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[177:181]
  case MCNotDefined:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[57:68]
  default:
    return ""
  }
}

// Unmarshal ModifiedCia from text.
func (v *ModifiedCia) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "NONE":
    *v = MCNone
    return nil
  case "LOW":
    *v = MCLow
    return nil
  case "HIGH":
    *v = MCHigh
    return nil
  case "NOT_DEFINED":
    *v = MCNotDefined
    return nil
  default:
    return fmt.Errorf("invalid ModifiedCia: \"%s\"", s)
  }
}

// Marshal ModifiedCia to text.
func (v *ModifiedCia) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Exploit Code Maturity
type ExploitCodeMaturity uint8

const (
  InvalidExploitCodeMaturity ExploitCodeMaturity = iota
  ECMUnproven
  ECMProofOfConcept
  ECMFunctional
  ECMHigh
  ECMNotDefined
)

// Convert ExploitCodeMaturity to string.
func (v ExploitCodeMaturity) String() string {
  switch v {
  case ECMUnproven:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[143:151]
  case ECMProofOfConcept:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[16:32]
  case ECMFunctional:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[79:89]
  case ECMHigh:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[177:181]
  case ECMNotDefined:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[57:68]
  default:
    return ""
  }
}

// Unmarshal ExploitCodeMaturity from text.
func (v *ExploitCodeMaturity) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "UNPROVEN":
    *v = ECMUnproven
    return nil
  case "PROOF_OF_CONCEPT":
    *v = ECMProofOfConcept
    return nil
  case "FUNCTIONAL":
    *v = ECMFunctional
    return nil
  case "HIGH":
    *v = ECMHigh
    return nil
  case "NOT_DEFINED":
    *v = ECMNotDefined
    return nil
  default:
    return fmt.Errorf("invalid ExploitCodeMaturity: \"%s\"", s)
  }
}

// Marshal ExploitCodeMaturity to text.
func (v *ExploitCodeMaturity) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Remediation Level
type RemediationLevel uint8

const (
  InvalidRemediationLevel RemediationLevel = iota
  RLOfficialFix
  RLTemporaryFix
  RLWorkaround
  RLUnavailable
  RLNotDefined
)

// Convert RemediationLevel to string.
func (v RemediationLevel) String() string {
  switch v {
  case RLOfficialFix:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[45:57]
  case RLTemporaryFix:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[32:45]
  case RLWorkaround:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[89:99]
  case RLUnavailable:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[68:79]
  case RLNotDefined:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[57:68]
  default:
    return ""
  }
}

// Unmarshal RemediationLevel from text.
func (v *RemediationLevel) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "OFFICIAL_FIX":
    *v = RLOfficialFix
    return nil
  case "TEMPORARY_FIX":
    *v = RLTemporaryFix
    return nil
  case "WORKAROUND":
    *v = RLWorkaround
    return nil
  case "UNAVAILABLE":
    *v = RLUnavailable
    return nil
  case "NOT_DEFINED":
    *v = RLNotDefined
    return nil
  default:
    return fmt.Errorf("invalid RemediationLevel: \"%s\"", s)
  }
}

// Marshal RemediationLevel to text.
func (v *RemediationLevel) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Confidence
type Confidence uint8

const (
  InvalidConfidence Confidence = iota
  CUnknown
  CReasonable
  CConfirmed
  CNotDefined
)

// Convert Confidence to string.
func (v Confidence) String() string {
  switch v {
  case CUnknown:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[159:166]
  case CReasonable:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[99:109]
  case CConfirmed:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[118:127]
  case CNotDefined:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[57:68]
  default:
    return ""
  }
}

// Unmarshal Confidence from text.
func (v *Confidence) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "UNKNOWN":
    *v = CUnknown
    return nil
  case "REASONABLE":
    *v = CReasonable
    return nil
  case "CONFIRMED":
    *v = CConfirmed
    return nil
  case "NOT_DEFINED":
    *v = CNotDefined
    return nil
  default:
    return fmt.Errorf("invalid Confidence: \"%s\"", s)
  }
}

// Marshal Confidence to text.
func (v *Confidence) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Cia Requirement
type CiaRequirement uint8

const (
  InvalidCiaRequirement CiaRequirement = iota
  CRLow
  CRMedium
  CRHigh
  CRNotDefined
)

// Convert CiaRequirement to string.
func (v CiaRequirement) String() string {
  switch v {
  case CRLow:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[185:188]
  case CRMedium:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[166:172]
  case CRHigh:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[177:181]
  case CRNotDefined:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[57:68]
  default:
    return ""
  }
}

// Unmarshal CiaRequirement from text.
func (v *CiaRequirement) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "LOW":
    *v = CRLow
    return nil
  case "MEDIUM":
    *v = CRMedium
    return nil
  case "HIGH":
    *v = CRHigh
    return nil
  case "NOT_DEFINED":
    *v = CRNotDefined
    return nil
  default:
    return fmt.Errorf("invalid CiaRequirement: \"%s\"", s)
  }
}

// Marshal CiaRequirement to text.
func (v *CiaRequirement) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Severity
type Severity uint8

const (
  InvalidSeverity Severity = iota
  SNone
  SLow
  SMedium
  SHigh
  SCritical
)

// Convert Severity to string.
func (v Severity) String() string {
  switch v {
  case SNone:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[181:185]
  case SLow:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[185:188]
  case SMedium:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[166:172]
  case SHigh:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[177:181]
  case SCritical:
    return _pack_ba6499cc006baa2f8f13f074011ebfd1[151:159]
  default:
    return ""
  }
}

// Unmarshal Severity from text.
func (v *Severity) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "NONE":
    *v = SNone
    return nil
  case "LOW":
    *v = SLow
    return nil
  case "MEDIUM":
    *v = SMedium
    return nil
  case "HIGH":
    *v = SHigh
    return nil
  case "CRITICAL":
    *v = SCritical
    return nil
  default:
    return fmt.Errorf("invalid Severity: \"%s\"", s)
  }
}

// Marshal Severity to text.
func (v *Severity) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}

