package v2

import (
  "math"
  "pmdn.org/nvd-go/cvss"
)

// Return pointer to float64 if the value is non-zero, or nil otherwise.
//
// Used by Scores() to handle temporal and environmental scores.
func maybeFloat(v float64) *float64 {
  if v > 0.0 {
    return &v
  } else {
    return nil
  }
}

// Return numerical scores for this vector.
func (v Vector) Scores() (cvss.Scores, error) {
  // CVSS v2 (https://www.first.org/cvss/v2/guide 3.2.1)
  //
  // Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
  // Exploitability = 20* AccessVector*AccessComplexity*Authentication
  // f(impact)= 0 if Impact=0, 1.176 otherwise
  // BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))

  // base score values
  confImpact := 0.0
  integImpact := 0.0
  availImpact := 0.0
  accessVector := 0.0
  accessComplexity := 0.0
  auth := 0.0

  // temporal score values
  // (FIXME: should these be set to 1.0?)
  exploitability := 0.0
  remediationLevel := 0.0
  reportConfidence := 0.0

  // env score values
  cdp := 0.0
  td := 0.0
  confReq := 0.0
  integReq := 0.0
  availReq := 0.0

  for _, m := range(v.Metrics()) {
    switch m {
    case AV_N: // AV:N
      accessVector = 1.0
    case AV_A: // AV:A
      accessVector = 0.646
    case AV_L: // AV:L
      accessVector = 0.395

    case AC_L: // AC:L
      accessComplexity = 0.71
    case AC_M: // AC:M
      accessComplexity = 0.61
    case AC_H: // AC:H
      accessComplexity = 0.35

    case Au_M: // Au:M
      auth = 0.45
    case Au_S: // Au:S
      auth = 0.56
    case Au_N: // Au:N
      auth = 0.704

    case C_N: // C:N
      confImpact = 0.0
    case C_P: // C:P
      confImpact = 0.275
    case C_C: // C:C
      confImpact = 0.660

    case I_N: // I:N
      integImpact = 0.0
    case I_P: // I:P
      integImpact = 0.275
    case I_C: // I:C
      integImpact = 0.660

    case A_N: // A:N
      availImpact = 0.0
    case A_P: // A:P
      availImpact = 0.275
    case A_C: // A:C
      availImpact = 0.660

    case E_ND: // E:ND
      exploitability = 1.0
    case E_U: // E:U
      exploitability = 0.85
    case E_POC: // E:POC
      exploitability = 0.9
    case E_F: // E:F
      exploitability = 0.95
    case E_H: // E:H
      exploitability = 1.0

    case RL_OF: // RL:OF
      remediationLevel = 0.87
    case RL_TF: // RL:TF
      remediationLevel = 0.9
    case RL_W: // RL:W
      remediationLevel = 0.95
    case RL_U: // RL:U
      remediationLevel = 1.0
    case RL_ND: // RL:ND
      remediationLevel = 1.0

    case RC_UC: // RC:UC
      reportConfidence = 0.9
    case RC_UR: // RC:UR
      reportConfidence = 0.95
    case RC_C: // RC:C
      reportConfidence = 1.0
    case RC_ND: // RC:ND
      reportConfidence = 1.0

    case CDP_N: // CDP:N
      cdp = 0.0
    case CDP_L: // CDP:L
      cdp = 0.1
    case CDP_LM: // CDP:LM
      cdp = 0.3
    case CDP_MH: // CDP:MH
      cdp = 0.4
    case CDP_H: // CDP:H
      cdp = 0.5
    case CDP_ND: // CDP:ND
      cdp = 0.0

    case TD_N: // TD:N
      td = 0.0
    case TD_L: // TD:L
      td = 0.25
    case TD_M: // TD:M
      td = 0.75
    case TD_H: // TD:H
      td = 1.0
    case TD_ND: // TD:ND
      td = 1.0

    case CR_L: // CR:L
      confReq = 0.5
    case CR_M: // CR:M
      confReq = 1.0
    case CR_H: // CR:H
      confReq = 1.51
    case CR_ND: // CR:ND
      confReq = 1.0

    case IR_L: // IR:L
      integReq = 0.5
    case IR_M: // IR:M
      integReq = 1.0
    case IR_H: // IR:H
      integReq = 1.51
    case IR_ND: // IR:ND
      integReq = 1.0

    case AR_L: // AR:L
      availReq = 0.5
    case AR_M: // AR:M
      availReq = 1.0
    case AR_H: // AR:H
      availReq = 1.51
    case AR_ND: // AR:ND
      availReq = 1.0
    }
  }

  // calculate base score (3.2.1 Base Equation)
  //
  // Impact = 10.41*(1-(1-ConfImpact)*(1-IntegImpact)*(1-AvailImpact))
  // Exploitability = 20* AccessVector*AccessComplexity*Authentication
  // f(impact)= 0 if Impact=0, 1.176 otherwise
  // BaseScore = round_to_1_decimal(((0.6*Impact)+(0.4*Exploitability)-1.5)*f(Impact))
  baseScore := 0.0
  {
    impact := 10.41 * (1 - (1 - confImpact) * (1 - integImpact) * (1 - availImpact))
    fImpact := 0.0
    if impact > 0.0 {
      fImpact = 1.176
    }
    baseExpl := 20 * accessVector * accessComplexity * auth
    baseScore = ((0.6 * impact + 0.4 * baseExpl) - 1.5) * fImpact
    baseScore = math.Round(10.0 * baseScore) / 10.0
  }

  // calculate temporal score (3.2.2 Temporal Equation)
  //
  // TemporalScore = round_to_1_decimal(BaseScore*Exploitability
  //                 *RemediationLevel*ReportConfidence)
  tempScore := 0.0
  {
    tempScore = baseScore * exploitability * remediationLevel * reportConfidence
    tempScore = math.Round(10.0 * tempScore) / 10.0
  }

  // calculate environmental score (3.2.3 Environmental Equation)
  //
  // AdjustedImpact = min(10,10.41*(1-(1-ConfImpact*ConfReq)*(1-IntegImpact*IntegReq)
  //                      *(1-AvailImpact*AvailReq)))
  //
  // AdjustedTemporal = TemporalScore recomputed with the BaseScore's
  // Impact sub-equation replaced with the AdjustedImpact equation
  //
  // EnvironmentalScore = round_to_1_decimal((AdjustedTemporal+
  // (10-AdjustedTemporal)*CollateralDamagePotential)*TargetDistribution)
  //
  envScore := 0.0
  {
    // calc adjusted impact
    adjImpact := math.Min(
      10.0,
      10.41 * (1 - (1 - confImpact * confReq) * (1 - integImpact * integReq) * (1 - availImpact * availReq)),
    )
    fImpact := 0.0
    if adjImpact > 0.0 {
      fImpact = 1.176
    }

    // calculate environmental base score using adjusted impact
    baseExpl := 20 * accessVector * accessComplexity * auth
    envBaseScore := ((0.6 * adjImpact + 0.4 * baseExpl) - 1.5) * fImpact
    envBaseScore = (10.0 * envBaseScore) / 10.0

    // calculate adjusted temporal score
    adjTempScore := envBaseScore * exploitability * remediationLevel * reportConfidence
    adjTempScore = math.Round(10.0 * adjTempScore) / 10.0

    envScore = (adjTempScore + (10 - adjTempScore) * cdp) * td
    envScore = math.Round(10.0 * envScore) / 10.0
  }

  // build and return result
  // FIXME: tempScore and envScore should be optional
  return cvss.NewScores(baseScore, maybeFloat(tempScore), maybeFloat(envScore))
}
