
// Enumerated string types.
//
// Automatically generated by `gen-enums.rb`.
package v2

import "fmt"

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
    return fmt.Errorf("invalid AccessVector: \"%s\"", s)
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
    return fmt.Errorf("invalid AccessComplexity: \"%s\"", s)
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
    return fmt.Errorf("invalid Authentication: \"%s\"", s)
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
    return fmt.Errorf("invalid Cia: \"%s\"", s)
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
    return fmt.Errorf("invalid Exploitability: \"%s\"", s)
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
    return fmt.Errorf("invalid RemediationLevel: \"%s\"", s)
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
    return fmt.Errorf("invalid ReportConfidence: \"%s\"", s)
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
    return fmt.Errorf("invalid CollateralDamagePotential: \"%s\"", s)
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
    return fmt.Errorf("invalid TargetDistribution: \"%s\"", s)
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
    return fmt.Errorf("invalid CiaRequirement: \"%s\"", s)
  }
}

// Marshal CiaRequirement to text.
func (v *CiaRequirement) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}

