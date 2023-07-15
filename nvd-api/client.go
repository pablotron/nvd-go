package nvd_api

import (
  "fmt"
  net_url "net/url"
  "pmdn.org/nvd-go/cve"
  "pmdn.org/nvd-go/cvss"
  "pmdn.org/nvd-go/rfc3339"
)

type Client struct {
  // API key
  apiKey string

  // API URL.
  apiUrl *net_url.URL
}

// Default NVD API URL.
var DefaultApiUrl = net_url.URL {
  Scheme: "https",
  Host: "services.nvd.nist.gov",
  Path: "/rest/json/cves/2.0",
}

// Create new REST API client from given API key and server URL.
func NewClientWithUrl(apiKey string, apiUrl *net_url.URL) Client {
  return Client { apiKey: apiKey, apiUrl: apiUrl }
}

// Create new REST API client from given API key.
func NewClient(apiKey string) Client {
  return NewClientWithUrl(apiKey, &DefaultApiUrl)
}

type LangString struct {
  Lang string `json:"lang"`
  Value string `json:"value"`
}

// CVSS version 2.0 version string.  Must be "2.0".
type CvssV2Version struct{}

func (v *CvssV2Version) UnmarshalText(text []byte) error {
  s := string(text)
  if s == "2.0" {
    return nil
  } else {
    return fmt.Errorf("invalid CVSS 2.0 version: \"%s\"", s)
  }
}

func (v *CvssV2Version) MarshalText() ([]byte, error) {
  return []byte("2.0"), nil
}

func (v CvssV2Version) String() string {
  return "2.0"
}

type CvssMetricsV2 []struct {
  Source string `json:"source"`
  Type string `json:"type"`
  CvssData struct {
    Version CvssV2Version `json:"version"` // must be "2.0"
    VectorString string `json:"vectorString"` // TODO: vector
    AccessVector string `json:"accessVector"`
    AccessComplexity string `json:"accessComplexity"`
    Authentication string `json:"authentication"`
    ConfidentialityImpact string `json:"confidentialityImpact"`
    IntegrityImpact string `json:"integrityImpact"`
    AvailabilityImpact string `json:"availabilityImpact"`
    BaseScore cvss.Score `json:"baseScore"`
    Exploitability string `json:"exploitability"`
  } `json:"cvssData"`
  BaseSeverity cvss.Severity `json:"baseSeverity"`
  ExploitabilityScore cvss.Score `json:"exploitabilityScore"`
}

type Vulnerability struct {
  Cve struct {
    Id cve.Id `json:"id"`
    SourceIdentifier *string `json:"sourceIdentifier"`
    VulnStatus *string `json:"vulnStatus"`
    Published *rfc3339.Time `json:"published"` // timestamp w/ ms
    LastModified *rfc3339.Time `json:"lastModified"` // timestamp w/ ms
    EvaluatorComment *string `json:"evaluatorComment"`
    EvaluatorSolution *string `json:"evaluatorSolution"`
    EvaluatorImpact *string `json:"evaluatorImpact"`
    CisaExploitAdd *rfc3339.Date `json:"cisaExploitAdd"`
    CisaActionDue *rfc3339.Date `json:"cisaActionDue"`
    CisaRequiredAction *rfc3339.Date `json:"cisaRequiredAction"`
    CisaVulnerabilityName *rfc3339.Date `json:"cisaVulnerabilityName"`
    Descriptions []LangString `json:"descriptions"`
    References []struct {
      Url string `json:"url"` // TODO: maxlen, prefix: (ftp|http)s
      Source string `json:"source"`
      Tags []string `json:"tags"`
    } `json:"references"`

    Metrics struct {
      CvssMetricsV2 []CvssMetricsV2 `json:"cvssMetricsV2"`
    } `json:"metrics"`
  } `json:"cve"`
}

type Results struct {
  ResultsPerPage int `json:"resultsPerPage"`
  StartIndex int `json:"startIndex"`
  TotalResults int `json:"totalResults"`
  Format string `json:"format"`
  Version string `json:"version"`
  Timestamp *rfc3339.Time `json:"timestamp"`
  Vulnerabilities *[]Vulnerability `json:"vulnerabilities"`
}

func (c Client) Cves(params CveParams) (*Results, error) {
  return nil, fmt.Errorf("TODO")
}
