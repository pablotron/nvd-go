package cvss

// CVSS score set.
type Scores struct {
  Base      Score `json:"base"`       // base score (required)
  Temporal  *Score `json:"temporal"`  // temporal score (optional)
  Env       *Score `json:"env"`       // environmental score (optional)
}

// Create new score set from floats.
func NewScores(base float64, temporal, env *float64) (Scores, error) {
  // convert base from float to Score
  baseScore, err := ParseScore(base)
  if err != nil {
    return Scores{}, err
  }

  var tempScore *Score
  if temporal != nil {
    // convert temporal from float to Score
    score, err := ParseScore(*temporal)
    if err != nil {
      return Scores{}, err
    }
    tempScore = &score
  }

  var envScore *Score
  if env != nil {
    // convert env from float to Score
    score, err := ParseScore(*env)
    if err != nil {
      return Scores{}, err
    }
    envScore = &score
  }

  // return success
  return Scores {
    Base: baseScore,
    Temporal: tempScore,
    Env: envScore,
  }, nil
}

// Create new score set from floats or panic on error.
func MustParseScores(base float64, temporal, env *float64) Scores {
  if scores, err := NewScores(base, temporal, env); err == nil {
    return scores
  } else {
    panic(err)
  }
}
