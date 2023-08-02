package url_params

import (
  "fmt"
  net_url "net/url"
  "reflect"
)

// Encode tagged structure as URL query string.
func Encode[T any](valPtr *T) (string, error) {
  if valPtr == nil {
    return "", nil
  }

  urlVals := net_url.Values {}
  structType := reflect.TypeOf((*T)(nil)).Elem()
  structVal := reflect.ValueOf(*valPtr)
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
        // FIXME: this should be appending boolean parameters without
        // the trailing "=", but Encode() still appends them for
        // multi-parameter strings
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
      if !fn.IsValid() {
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
