
// Enumerated string types.
//
// Automatically generated by `gen-enums.rb`.
package cvss2

import "fmt"

// Invalid type string error
type InvalidTypeString struct {
  Type, Value string
}

func newInvalidTypeString(typeName, value string) *InvalidTypeString {
  return &InvalidTypeString { typeName, value }
}

func (t InvalidTypeString) Error() string {
  return fmt.Sprintf("invalid %s: \"%s\"", t.Type, t.Value)
}

// packed string of enumeration values
const _pack_1b2f6a71ad5e2fab32a7807dde521a4d = `ADJACENT_NETWORKPROOF_OF_CONCEPTUNCORROBORATEDTEMPORARY_FIXOFFICIAL_FIXNOT_DEFINEDUNAVAILABLEUNCONFIRMEDMEDIUM_HIGHFUNCTIONALWORKAROUNDLOW_MEDIUMMULTIPLECOMPLETEUNPROVENPARTIALSINGLELOCALNONE`


// Access Vector
type AccessVector uint8

const (
  InvalidAccessVector AccessVector = iota
  AVNetwork
  AVAdjacentNetwork
  AVLocal
)

// Parse AccessVector from string.
func ParseAccessVector(s string) (AccessVector, error) {
  switch s {
  case "NETWORK":
    return AVNetwork, nil
  case "ADJACENT_NETWORK":
    return AVAdjacentNetwork, nil
  case "LOCAL":
    return AVLocal, nil
  default:
    return InvalidAccessVector, newInvalidTypeString("AccessVector", s)
  }
}

// Convert AccessVector to string.
func (v AccessVector) String() string {
  switch v {
  case AVNetwork:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[9:16]
  case AVAdjacentNetwork:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[0:16]
  case AVLocal:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[182:187]
  default:
    return ""
  }
}

// Unmarshal AccessVector from text.
func (v *AccessVector) UnmarshalText(text []byte) error {
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
  default:
    return newInvalidTypeString("AccessVector", s)
  }
}

// Marshal AccessVector to text.
func (v *AccessVector) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Access Complexity
type AccessComplexity uint8

const (
  InvalidAccessComplexity AccessComplexity = iota
  ACHigh
  ACMedium
  ACLow
)

// Parse AccessComplexity from string.
func ParseAccessComplexity(s string) (AccessComplexity, error) {
  switch s {
  case "HIGH":
    return ACHigh, nil
  case "MEDIUM":
    return ACMedium, nil
  case "LOW":
    return ACLow, nil
  default:
    return InvalidAccessComplexity, newInvalidTypeString("AccessComplexity", s)
  }
}

// Convert AccessComplexity to string.
func (v AccessComplexity) String() string {
  switch v {
  case ACHigh:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[111:115]
  case ACMedium:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[104:110]
  case ACLow:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[135:138]
  default:
    return ""
  }
}

// Unmarshal AccessComplexity from text.
func (v *AccessComplexity) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "HIGH":
    *v = ACHigh
    return nil
  case "MEDIUM":
    *v = ACMedium
    return nil
  case "LOW":
    *v = ACLow
    return nil
  default:
    return newInvalidTypeString("AccessComplexity", s)
  }
}

// Marshal AccessComplexity to text.
func (v *AccessComplexity) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Authentication
type Authentication uint8

const (
  InvalidAuthentication Authentication = iota
  AMultiple
  ASingle
  ANone
)

// Parse Authentication from string.
func ParseAuthentication(s string) (Authentication, error) {
  switch s {
  case "MULTIPLE":
    return AMultiple, nil
  case "SINGLE":
    return ASingle, nil
  case "NONE":
    return ANone, nil
  default:
    return InvalidAuthentication, newInvalidTypeString("Authentication", s)
  }
}

// Convert Authentication to string.
func (v Authentication) String() string {
  switch v {
  case AMultiple:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[145:153]
  case ASingle:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[176:182]
  case ANone:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[187:191]
  default:
    return ""
  }
}

// Unmarshal Authentication from text.
func (v *Authentication) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "MULTIPLE":
    *v = AMultiple
    return nil
  case "SINGLE":
    *v = ASingle
    return nil
  case "NONE":
    *v = ANone
    return nil
  default:
    return newInvalidTypeString("Authentication", s)
  }
}

// Marshal Authentication to text.
func (v *Authentication) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Cia
type Cia uint8

const (
  InvalidCia Cia = iota
  CNone
  CPartial
  CComplete
)

// Parse Cia from string.
func ParseCia(s string) (Cia, error) {
  switch s {
  case "NONE":
    return CNone, nil
  case "PARTIAL":
    return CPartial, nil
  case "COMPLETE":
    return CComplete, nil
  default:
    return InvalidCia, newInvalidTypeString("Cia", s)
  }
}

// Convert Cia to string.
func (v Cia) String() string {
  switch v {
  case CNone:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[187:191]
  case CPartial:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[169:176]
  case CComplete:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[153:161]
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
  case "PARTIAL":
    *v = CPartial
    return nil
  case "COMPLETE":
    *v = CComplete
    return nil
  default:
    return newInvalidTypeString("Cia", s)
  }
}

// Marshal Cia to text.
func (v *Cia) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Exploitability
type Exploitability uint8

const (
  InvalidExploitability Exploitability = iota
  EUnproven
  EProofOfConcept
  EFunctional
  EHigh
  ENotDefined
)

// Parse Exploitability from string.
func ParseExploitability(s string) (Exploitability, error) {
  switch s {
  case "UNPROVEN":
    return EUnproven, nil
  case "PROOF_OF_CONCEPT":
    return EProofOfConcept, nil
  case "FUNCTIONAL":
    return EFunctional, nil
  case "HIGH":
    return EHigh, nil
  case "NOT_DEFINED":
    return ENotDefined, nil
  default:
    return InvalidExploitability, newInvalidTypeString("Exploitability", s)
  }
}

// Convert Exploitability to string.
func (v Exploitability) String() string {
  switch v {
  case EUnproven:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[161:169]
  case EProofOfConcept:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[16:32]
  case EFunctional:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[115:125]
  case EHigh:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[111:115]
  case ENotDefined:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[71:82]
  default:
    return ""
  }
}

// Unmarshal Exploitability from text.
func (v *Exploitability) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "UNPROVEN":
    *v = EUnproven
    return nil
  case "PROOF_OF_CONCEPT":
    *v = EProofOfConcept
    return nil
  case "FUNCTIONAL":
    *v = EFunctional
    return nil
  case "HIGH":
    *v = EHigh
    return nil
  case "NOT_DEFINED":
    *v = ENotDefined
    return nil
  default:
    return newInvalidTypeString("Exploitability", s)
  }
}

// Marshal Exploitability to text.
func (v *Exploitability) MarshalText() ([]byte, error) {
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

// Parse RemediationLevel from string.
func ParseRemediationLevel(s string) (RemediationLevel, error) {
  switch s {
  case "OFFICIAL_FIX":
    return RLOfficialFix, nil
  case "TEMPORARY_FIX":
    return RLTemporaryFix, nil
  case "WORKAROUND":
    return RLWorkaround, nil
  case "UNAVAILABLE":
    return RLUnavailable, nil
  case "NOT_DEFINED":
    return RLNotDefined, nil
  default:
    return InvalidRemediationLevel, newInvalidTypeString("RemediationLevel", s)
  }
}

// Convert RemediationLevel to string.
func (v RemediationLevel) String() string {
  switch v {
  case RLOfficialFix:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[59:71]
  case RLTemporaryFix:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[46:59]
  case RLWorkaround:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[125:135]
  case RLUnavailable:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[82:93]
  case RLNotDefined:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[71:82]
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
    return newInvalidTypeString("RemediationLevel", s)
  }
}

// Marshal RemediationLevel to text.
func (v *RemediationLevel) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Report Confidence
type ReportConfidence uint8

const (
  InvalidReportConfidence ReportConfidence = iota
  RCUnconfirmed
  RCUncorroborated
  RCConfirmed
  RCNotDefined
)

// Parse ReportConfidence from string.
func ParseReportConfidence(s string) (ReportConfidence, error) {
  switch s {
  case "UNCONFIRMED":
    return RCUnconfirmed, nil
  case "UNCORROBORATED":
    return RCUncorroborated, nil
  case "CONFIRMED":
    return RCConfirmed, nil
  case "NOT_DEFINED":
    return RCNotDefined, nil
  default:
    return InvalidReportConfidence, newInvalidTypeString("ReportConfidence", s)
  }
}

// Convert ReportConfidence to string.
func (v ReportConfidence) String() string {
  switch v {
  case RCUnconfirmed:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[93:104]
  case RCUncorroborated:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[32:46]
  case RCConfirmed:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[95:104]
  case RCNotDefined:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[71:82]
  default:
    return ""
  }
}

// Unmarshal ReportConfidence from text.
func (v *ReportConfidence) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "UNCONFIRMED":
    *v = RCUnconfirmed
    return nil
  case "UNCORROBORATED":
    *v = RCUncorroborated
    return nil
  case "CONFIRMED":
    *v = RCConfirmed
    return nil
  case "NOT_DEFINED":
    *v = RCNotDefined
    return nil
  default:
    return newInvalidTypeString("ReportConfidence", s)
  }
}

// Marshal ReportConfidence to text.
func (v *ReportConfidence) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Collateral Damage Potential
type CollateralDamagePotential uint8

const (
  InvalidCollateralDamagePotential CollateralDamagePotential = iota
  CDPNone
  CDPLow
  CDPLowMedium
  CDPMediumHigh
  CDPHigh
  CDPNotDefined
)

// Parse CollateralDamagePotential from string.
func ParseCollateralDamagePotential(s string) (CollateralDamagePotential, error) {
  switch s {
  case "NONE":
    return CDPNone, nil
  case "LOW":
    return CDPLow, nil
  case "LOW_MEDIUM":
    return CDPLowMedium, nil
  case "MEDIUM_HIGH":
    return CDPMediumHigh, nil
  case "HIGH":
    return CDPHigh, nil
  case "NOT_DEFINED":
    return CDPNotDefined, nil
  default:
    return InvalidCollateralDamagePotential, newInvalidTypeString("CollateralDamagePotential", s)
  }
}

// Convert CollateralDamagePotential to string.
func (v CollateralDamagePotential) String() string {
  switch v {
  case CDPNone:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[187:191]
  case CDPLow:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[135:138]
  case CDPLowMedium:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[135:145]
  case CDPMediumHigh:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[104:115]
  case CDPHigh:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[111:115]
  case CDPNotDefined:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[71:82]
  default:
    return ""
  }
}

// Unmarshal CollateralDamagePotential from text.
func (v *CollateralDamagePotential) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "NONE":
    *v = CDPNone
    return nil
  case "LOW":
    *v = CDPLow
    return nil
  case "LOW_MEDIUM":
    *v = CDPLowMedium
    return nil
  case "MEDIUM_HIGH":
    *v = CDPMediumHigh
    return nil
  case "HIGH":
    *v = CDPHigh
    return nil
  case "NOT_DEFINED":
    *v = CDPNotDefined
    return nil
  default:
    return newInvalidTypeString("CollateralDamagePotential", s)
  }
}

// Marshal CollateralDamagePotential to text.
func (v *CollateralDamagePotential) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}


// Target Distribution
type TargetDistribution uint8

const (
  InvalidTargetDistribution TargetDistribution = iota
  TDNone
  TDLow
  TDMedium
  TDHigh
  TDNotDefined
)

// Parse TargetDistribution from string.
func ParseTargetDistribution(s string) (TargetDistribution, error) {
  switch s {
  case "NONE":
    return TDNone, nil
  case "LOW":
    return TDLow, nil
  case "MEDIUM":
    return TDMedium, nil
  case "HIGH":
    return TDHigh, nil
  case "NOT_DEFINED":
    return TDNotDefined, nil
  default:
    return InvalidTargetDistribution, newInvalidTypeString("TargetDistribution", s)
  }
}

// Convert TargetDistribution to string.
func (v TargetDistribution) String() string {
  switch v {
  case TDNone:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[187:191]
  case TDLow:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[135:138]
  case TDMedium:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[104:110]
  case TDHigh:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[111:115]
  case TDNotDefined:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[71:82]
  default:
    return ""
  }
}

// Unmarshal TargetDistribution from text.
func (v *TargetDistribution) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "NONE":
    *v = TDNone
    return nil
  case "LOW":
    *v = TDLow
    return nil
  case "MEDIUM":
    *v = TDMedium
    return nil
  case "HIGH":
    *v = TDHigh
    return nil
  case "NOT_DEFINED":
    *v = TDNotDefined
    return nil
  default:
    return newInvalidTypeString("TargetDistribution", s)
  }
}

// Marshal TargetDistribution to text.
func (v *TargetDistribution) MarshalText() ([]byte, error) {
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

// Parse CiaRequirement from string.
func ParseCiaRequirement(s string) (CiaRequirement, error) {
  switch s {
  case "LOW":
    return CRLow, nil
  case "MEDIUM":
    return CRMedium, nil
  case "HIGH":
    return CRHigh, nil
  case "NOT_DEFINED":
    return CRNotDefined, nil
  default:
    return InvalidCiaRequirement, newInvalidTypeString("CiaRequirement", s)
  }
}

// Convert CiaRequirement to string.
func (v CiaRequirement) String() string {
  switch v {
  case CRLow:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[135:138]
  case CRMedium:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[104:110]
  case CRHigh:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[111:115]
  case CRNotDefined:
    return _pack_1b2f6a71ad5e2fab32a7807dde521a4d[71:82]
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
    return newInvalidTypeString("CiaRequirement", s)
  }
}

// Marshal CiaRequirement to text.
func (v *CiaRequirement) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}

