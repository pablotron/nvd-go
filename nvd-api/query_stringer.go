package nvd_api

type QueryStringer interface {
  // Convert structure to query string.
  QueryString() (string, error)
}
