package v31

import (
  "math"
  "pmdn.org/nvd-go/cvss"
)

// metric coefficients
// (borrowed old cvez code)
var metricCoefs = map[Metric]float64 {
  AV_N: 0.85, // AV:N
  AV_A: 0.62, // AV:A
  AV_L: 0.55, // AV:L
  AV_P: 0.2, // AV:P

  AC_L: 0.77, // AC:L
  AC_H: 0.44, // AC:H

  PR_N: 0.85, // PR:N
  PR_L: 0.62, // PR:L
  PR_H: 0.27, // PR:H

  UI_N: 0.85, // UI:N
  UI_R: 0.62, // UI:R

  C_H: 0.56, // C:H
  C_L: 0.22, // C:L
  C_N: 0.0, // C:N

  I_H: 0.56, // I:H
  I_L: 0.22, // I:L
  I_N: 0.0, // I:N

  A_H: 0.56, // A:H
  A_L: 0.22, // A:L
  A_N: 0.0, // A:N

  E_X: 1.0, // E:X
  E_H: 1.0, // E:H
  E_F: 0.97, // E:F
  E_P: 0.94, // E:P
  E_U: 0.91, // E:U

  RL_X: 1.0, // RL:X
  RL_U: 1.0, // RL:U
  RL_W: 0.97, // RL:W
  RL_T: 0.96, // RL:T
  RL_O: 0.95, // RL:O

  RC_X: 1.0, // RC:X
  RC_C: 1.0, // RC:C
  RC_R: 0.96, // RC:R
  RC_U: 0.92, // RC:U

  CR_X: 1.0, // CR:X
  CR_H: 1.5, // CR:H
  CR_M: 1.0, // CR:M
  CR_L: 0.5, // CR:L

  IR_X: 1.0, // IR:X
  IR_H: 1.5, // IR:H
  IR_M: 1.0, // IR:M
  IR_L: 0.5, // IR:L

  AR_X: 1.0, // AR:X
  AR_H: 1.5, // AR:H
  AR_M: 1.0, // AR:M
  AR_L: 0.5, // AR:L

  MAV_X: 1.0, // MAV:X
  MAV_N: 0.85, // MAV:N
  MAV_A: 0.62, // MAV:A
  MAV_L: 0.55, // MAV:L
  MAV_P: 0.2, // MAV:P

  MAC_X: 1.0, // MAC:X
  MAC_L: 0.77, // MAC:L
  MAC_H: 0.44, // MAC:H

  MPR_X: 1.0, // MPR:X
  MPR_N: 0.85, // MPR:N
  MPR_L: 0.62, // MPR:L
  MPR_H: 0.27, // MPR:H

  MUI_X: 1.0, // MUI:X
  MUI_N: 0.85, // MUI:N
  MUI_R: 0.62, // MUI:R

  MC_X: 1.0, // MC:X
  MC_H: 0.56, // MC:H
  MC_L: 0.22, // MC:L
  MC_N: 0.0, // MC:N

  MI_X: 1.0, // MI:X
  MI_H: 0.56, // MI:H
  MI_L: 0.22, // MI:L
  MI_N: 0.0, // MI:N

  MA_X: 1.0, // MA:X
  MA_H: 0.56, // MA:H
  MA_L: 0.22, // MA:L
  MA_N: 0.0, // MA:N
}

// privilege required coefficients
var privReqCoefs = map[Metric]map[bool]float64 {
  PR_N: map[bool]float64 { false: 0.85, true: 0.85 },
  PR_L: map[bool]float64 { false: 0.62, true: 0.68 },
  PR_H: map[bool]float64 { false: 0.27, true: 0.50 },
  MPR_N: map[bool]float64 { false: 0.85, true: 0.85 },
  MPR_L: map[bool]float64 { false: 0.62, true: 0.68 },
  MPR_H: map[bool]float64 { false: 0.27, true: 0.50 },
}

// Get modified metric coefficient, or fall back to base coefficient if
// modified metric is not defined.
func getModCoef(keys map[Key]Metric, modKey, baseKey Key) float64 {
  if m := keys[modKey]; m.Value() != NotDefined {
    // return modified metric coefficient
    return metricCoefs[m]
  } else {
    // return base coefficient
    return metricCoefs[keys[baseKey]]
  }
}

// Does the map have at least one of the keys needed for a temporal
// score defined?
func hasTemporalScoreKeys(keys map[Key]Metric) bool {
  ecm, ecm_ok := keys[E] // E
  rl, rl_ok := keys[RL] // RL
  rc, rc_ok := keys[RC] // RC

  return (ecm_ok && ecm.Value() != NotDefined) ||
         (rl_ok && rl.Value() != NotDefined) ||
         (rc_ok && rc.Value() != NotDefined)
}

// Does the map have at least one of the keys needed for an env score to
// be defined?
func hasEnvScoreKeys(keys map[Key]Metric) bool {
  mav, mav_ok := keys[MAV] // MAV
  mac, mac_ok := keys[MAC] // MAC
  mpr, mpr_ok := keys[MPR] // MPR
  mui, mui_ok := keys[MUI] // MUI
  ms, ms_ok := keys[MS] // MS
  mc, mc_ok := keys[MC] // MC
  mi, mi_ok := keys[MI] // MI
  ma, ma_ok := keys[MA] // MA
  cr, cr_ok := keys[CR] // CR
  ir, ir_ok := keys[IR] // IR
  ar, ar_ok := keys[AR] // AR

  return (mav_ok && mav.Value() != NotDefined) ||
         (mac_ok && mac.Value() != NotDefined) ||
         (mpr_ok && mpr.Value() != NotDefined) ||
         (mui_ok && mui.Value() != NotDefined) ||
         (ms_ok && ms.Value() != NotDefined) ||
         (mc_ok && mc.Value() != NotDefined) ||
         (mi_ok && mi.Value() != NotDefined) ||
         (ma_ok && ma.Value() != NotDefined) ||
         (cr_ok && cr.Value() != NotDefined) ||
         (ir_ok && ir.Value() != NotDefined) ||
         (ar_ok && ar.Value() != NotDefined);
}

// roundup implemention (from CVSS v3.1 spec, appendix A)
func roundup(val float64) float64 {
  return math.Ceil(10.0 * val) / 10.0
}

// Return numerical scores for this vector.
//
// Reference implementation: https://www.first.org/cvss/calculator/cvsscalc31.js
func (v Vector) Scores() (cvss.Scores, error) {
  scopeChanged := false
  modScopeChanged := false

  // default metrics map
  keys := map[Key]Metric {
    E: E_X,
    RL: RL_X,
    RC: RC_X,
    CR: CR_X,
    IR: IR_X,
    AR: AR_X,
    MAV: MAV_X,
    MAC: MAC_X,
    MPR: MPR_X,
    MUI: MUI_X,
    MS: MS_X,
    MC: MC_X,
    MI: MI_X,
    MA: MA_X,
  }

  // populate metrics map
  for _, m := range(v.Metrics()) {
    keys[m.Key()] = m

    switch m.Key() {
    case S:
      scopeChanged = m.Value() == Changed
    case MS:
      modScopeChanged = m.Value() == Changed
    }
  }

  attackVector := metricCoefs[keys[AV]]
  attackComplexity := metricCoefs[keys[AC]]
  userInteraction := metricCoefs[keys[UI]]
  conf := metricCoefs[keys[C]]
  integ := metricCoefs[keys[I]]
  avail := metricCoefs[keys[A]]
  ecm := metricCoefs[keys[E]]
  remediationLevel := metricCoefs[keys[RL]]
  reportConfidence := metricCoefs[keys[RC]]
  confReq := metricCoefs[keys[CR]]
  availReq := metricCoefs[keys[AR]]
  integReq := metricCoefs[keys[IR]]

  // adjust privsRequired based on scopeChanged
  // (CVSS v3.1 spec, section 7.4, table 16)
  privsRequired := privReqCoefs[keys[PR]][scopeChanged]

  modAttackVector := getModCoef(keys, MAV, AV)
  modAttackComplexity := getModCoef(keys, MAC, AC)
  modUserInteraction := getModCoef(keys, MUI, UI)
  modConf := getModCoef(keys, MC, C)
  modInteg := getModCoef(keys, MI, I)
  modAvail := getModCoef(keys, MA, A)

  if m := keys[MS]; m == MS_X {
    // default to base scopeChanged
    modScopeChanged = scopeChanged
  }

  // adjust modPrivsRequired based on scopeChanged
  // (CVSS v3.1 spec, section 7.4, table 16)
  modPrivsRequired := 0.0
  {
    mpr := keys[MPR]
    pr := keys[PR]
    ms := keys[MS]

    if mpr != MPR_X && ms != MS_X {
      modPrivsRequired = privReqCoefs[mpr][ms == MS_C]
    } else if mpr != MPR_X && ms == MS_X {
      modPrivsRequired = privReqCoefs[mpr][scopeChanged]
    } else if mpr == MPR_X && ms != MS_X {
      modPrivsRequired = privReqCoefs[pr][ms == MS_C]
    } else {
      // default to base privsRequired
      // modPrivsRequired = privsRequired
      modPrivsRequired = privReqCoefs[pr][scopeChanged]
    }
  }

  // calculate base score (CVSS v3.1 spec, section 7.1)
  baseScore := 0.0
  {
    // calculate impact sub-score (cvss v3.1 spec, section 7.1)
    iss := 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))

    // calculate impact
    impact := 0.0
    if scopeChanged {
      impact = 7.52 * (iss - 0.029) - 3.25 * math.Pow(iss - 0.02, 15)
    } else {
      impact = 6.42 * iss
    }

    // exploitability
    expl := 8.22 * attackVector * attackComplexity * privsRequired * userInteraction

    if impact <= 0.0 {
      baseScore = 0
    } else if scopeChanged {
      baseScore = roundup(math.Min(1.08 * (impact + expl), 10.0))
    } else {
      baseScore = roundup(math.Min(impact + expl, 10.0))
    }
  }

  // temporal score (CVSS v3.1 spec, section 7.2)
  var tempScore *float64
  if hasTemporalScoreKeys(keys) {
    tmp := roundup(baseScore * ecm * remediationLevel * reportConfidence)
    tempScore = &tmp
  }

  // environmental score (CVSS v3.1 spec, section 7.3)
  var envScore *float64
  if hasEnvScoreKeys(keys) {
    // modified impact sub score (ISC_m)
    miss := math.Min(
      1 - (1 - confReq * modConf) * (1 - integReq * modInteg) * (1 - availReq * modAvail),
      0.915,
    )

    // modified impact
    // NOTE: exponent of 13 differs for CVSS v3.0 and CVSS v3.1
    impact := 0.0
    if modScopeChanged {
      impact = 7.52 * (miss - 0.029) - 3.25 * math.Pow(miss * 0.9731 - 0.02, 13)
    } else {
      impact = 6.42 * miss
    }

    // modified exploitability sub score
    expl := 8.22 * modAttackVector * modAttackComplexity * modPrivsRequired * modUserInteraction

    // calculate env score
    if impact <= 0.0 {
      tmp := float64(0.0)
      envScore = &tmp
    } else if modScopeChanged {
      // Roundup(Roundup[Minimum(1.08 × [ModifiedImpact + ModifiedExploitability], 10)] × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
      tmp := roundup(roundup(math.Min(1.08 * (impact + expl), 10.0)) * ecm * remediationLevel * reportConfidence)
      envScore = &tmp
    } else {
      // Roundup(Roundup[Minimum([ModifiedImpact + ModifiedExploitability], 10) ] × ExploitCodeMaturity × RemediationLevel × ReportConfidence)
      tmp := roundup(roundup(math.Min((impact + expl), 10.0)) * ecm * remediationLevel * reportConfidence)
      envScore = &tmp
    }
  }

  // build and return new scores
  return cvss.NewScores(baseScore, tempScore, envScore)
}
