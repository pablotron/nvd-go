package nvd_api

// Interface used by Client.send() to marshal tagged structure as URL
// query string.
type QueryStringer interface {
  // Convert tagged structure fields to URL query string.
  QueryString() (string, error)
}
