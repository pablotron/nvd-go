package cvss

// CVSS vector.
type Vector interface {
  // Get string representation of CVSS vector.
  String() string

  // Get scores for CVSS vector.
  Scores() (Scores, error)

  // get CVSS version
  Version() Version
}
