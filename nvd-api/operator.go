package nvd_api

import "fmt"

// Configuration boolean operator (AND or OR).
type Operator byte

const (
  InvalidOperator Operator = iota
  And // AND
  Or // OR
)

// Unmarshal configuration operator.
func (o *Operator) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {
  case "AND":
    *o = And
    return nil
  case "OR":
    *o = Or
    return nil
  default:
    return fmt.Errorf("invalid configuration operator: \"%s\"", s)
  }
}

// Marshal configuration operator to text.
func (o *Operator) MarshalText() ([]byte, error) {
  return []byte(o.String()), nil
}

// Convert configuration operator to string.
func (o Operator) String() string {
  switch o {
  case And:
    return "AND"
  case Or:
    return "OR"
  default:
    return ""
  }
}
