package nvd_api

import "fmt"

// Configuration boolean operator (AND or OR).
type Operator byte

const (
  InvalidOperator Operator = iota
  And // AND
  Or // OR
)

// Map of string to configuration operator.  Used by `UnmarshalText()`.
var operatorStrMap = map[string]Operator {
  "AND": And,
  "OR": Or,
}

// Unmarshal configuration operator.
func (o *Operator) UnmarshalText(text []byte) error {
  s := string(text)
  if no, ok := operatorStrMap[s]; ok {
    *o = no
    return nil
  } else {
    return fmt.Errorf("invalid configuration operator: \"%s\"", s)
  }
}

// Marshal configuration operator to text.
func (o *Operator) MarshalText() ([]byte, error) {
  return []byte(o.String()), nil
}

// Configuration operator strings.  Used by `String()`.
var operatorStrs = [...]string {
  "",
  "AND",
  "OR",
}

// Convert configuration operator to string.
func (o Operator) String() string {
  if int(o) < len(operatorStrs) {
    return operatorStrs[int(o)]
  } else {
    return ""
  }
}
