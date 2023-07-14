package nvd

import (
  "fmt"
  net_url "net/url"
  "reflect"
)

// Search parameters for `Cves()` method.
type CveParams struct {
  CpeName *CpeName `url:"cpeName"`
  CveId *CveId `url:"cveId"`
  CvssV2Metrics string `url:"cvssV2Metrics"`
  CvssV2Severity string `url:"cvssV2Severity"`
  CvssV3Metrics string `url:"cvssV3Metrics"`
  CvssV3Severity string `url:"cvssV3Severity"`
  CweId string `url:"cweId"`
  HasCertAlerts bool `url:"hasCertAlerts"`
  HasCertNotes bool `url:"hasCertNotes"`
  HasKev bool `url:"hasKev"`
  HasOval bool `url:"hasOval"`
  IsVulnerable bool `url:"isVulnerable"`
  KeywordExactMatch bool `url:"keywordExactMatch"`
  KeywordSearch string `url:"keywordSearch"`
  LastModStartDate *Time `url:"lastModStartDate"`
  LastModEndDate *Time `url:"lastModEndDate"`
  NoRejected bool `url:"noRejected"`
  PubStartDate *Time `url:"pubStartDate"`
  PubEndDate *Time `url:"pubEndDate"`
  ResultsPerPage uint `url:"resultsPerPage"`
  StartIndex uint `url:"startIndex"`
  SourceIdentifier string `url:"sourceIdentifier"`
  VersionStart string `url:"versionStart"`
  VersionStartType VersionType `url:"versionStartType"`
  VersionEnd string `url:"versionEnd"`
  VersionEndType  VersionType `url:"versionEndType"`
  VirtualMatchString string `url:"virtualMatchString"`
}

// Get parameters encoded as URL query string.
//
// Returns an error if any of the search parameters are invalid or if an
// invalid combination of search parameters was provided.
func (cp *CveParams) QueryString() (string, error) {
  urlVals := net_url.Values {}
  structType := reflect.TypeOf(cp).Elem()
  structVal := reflect.ValueOf(*cp)
  for i := 0; i < structType.NumField(); i++ {
    // get field
    field := structType.Field(i)
    if !field.IsExported() {
      continue
    }

    // get field tag
    tag, ok := field.Tag.Lookup("url")
    if !ok {
      continue
    }

    // get field value
    fieldVal := structVal.Field(i)
    if fieldVal.IsZero() {
      continue
    }

    switch fieldVal.Type().Kind() {
    case reflect.Bool:
      if val := fieldVal.Bool(); val {
        urlVals.Add(tag, "")
      }
    case reflect.Uint:
      if val := fieldVal.Uint(); val > 0 {
        urlVals.Add(tag, fmt.Sprintf("%d", val))
      }
    case reflect.String:
      if val := fieldVal.String(); val != "" {
        urlVals.Add(tag, val)
      }
    default:
      // get String() method
      fn := fieldVal.MethodByName("String")
      if fn.IsZero() {
        return "", fmt.Errorf("field %s cannot be converted to string", field.Name)
      }

      // invoke String() method
      if val := fn.Call([]reflect.Value{})[0].String(); val != "" {
        urlVals.Add(tag, val)
      }
    }
  }

  // return parameters encoded as URL query sting
  return urlVals.Encode(), nil
}
