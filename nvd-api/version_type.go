package nvd_api

// Value which indicates whether a version match range is inclusive or
// exclusive.  Used as parameter in `CvesParams` structure.
type VersionType byte

const (
  DefaultVersionType VersionType = iota
  Including // Inclusive range endpoint.
  Excluding // Exclusive range endpoint.
)

// Return version type as string.  Returns "<invalid>" if the type is
// not a valid VersionType.
func (t VersionType) String() string {
  switch t {
  case DefaultVersionType:
    return ""
  case Including:
    return "including"
  case Excluding:
    return "excluding"
  default:
    return "<invalid>"
  }
}
