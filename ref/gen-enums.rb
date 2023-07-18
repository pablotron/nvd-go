#!/usr/bin/env ruby
# frozen_string_literal: true

#
# gen-enums.rb: generate enum code for given JSON schema.
#
# Example:
#   ./gen-enums.rb cvss31 < cvss-v3.1.json > cvss31/cvss31.go
#
# TODO: should be rewritten to work with `go generate`.
#

# load libraries
require 'json'
require 'digest/sha2'

# templates
T = {
  main: %{
// Enumerated string types.
//
// Automatically generated by `gen-enums.rb`.
package %<ns>s

import "fmt"

// Invalid type string error
type InvalidTypeString struct {
  Type, Value string
}

func newInvalidTypeString(type, value string) &InvalidTypeString {
  return &InvalidTypeString { type, value }
}

func (e InvalidTypeString) Error() string {
  return fmt.Sprintf("invalid %%s: \\"%%s\\"", t.Type, t.Value)
}

// packed string of enumeration values
const %<pack>s = `%<pack_data>s`

%<enums>s
},

  enum_name: '%<type_acronym>s%<name>s',

  enum: %(
// %<comment>s
type %<type>s uint8

const (
  Invalid%<type>s %<type>s = iota%<consts>s
)

// Parse %<type>s from string.
func Parse%<type>s(s string) (%<type>s, error) {
  switch s {%<parse_cases>s
    return Invalid%<type>s, newInvalidTypeString("%<type>s", s)
  }
}

// Convert %<type>s to string.
func (v %<type>s) String() string {
  switch v {%<string_cases>s
  default:
    return ""
  }
}

// Unmarshal %<type>s from text.
func (v *%<type>s) UnmarshalText(text []byte) error {
  s := string(text)
  switch string(text) {%<unmarshal_cases>s
  default:
    return newInvalidTypeString("%<type>s", s)
  }
}

// Marshal %<type>s to text.
func (v *%<type>s) MarshalText() ([]byte, error) {
  return []byte(v.String()), nil
}
),

  const: %{
  %<name>s},

  parse_case: %{
  case "%<val>s":
    return %<name>s, nil},

  string_case: %{
  case %<name>s:
    return %<pack>s[%<ofs>d:%<len>d]},

  unmarshal_case: %{
  case "%<val>s":
    *v = %<name>s
    return nil},
}.freeze

class Type
  attr_reader :id, :title, :acronym, :comment

  def initialize(id)
    
    # remove "Type" suffix
    id = id.gsub(/Type$/, '')

    # build title
    @title = id.dup
    @title[0] = id[0].upcase

    # build comment
    @comment = id.size.times.each_with_object([]) do |i, r|
      c = id[i]
      u = c.upcase

      if i == 0
        r << u
      elsif c == u
        r << " #{u}"
      else
        r << c
      end
    end.join

    # build acronym
    @acronym = id.size.times.each_with_object([]) do |i, r|
      c = id[i]
      r << c.upcase if ((i == 0) || c == c.upcase)
    end.join
  end
end

#
# Build packed string of enum string values.
#
# Works by sorting enum values by length from longest to shortest; by
# definition if there are overlapping strings then shorter strings will
# will be subsets of longer strings
#
def to_packed(enums)
  # build list of unique string enum vals
  strs = enums.values.map { |row| row['enum'] }.flatten.uniq
  
  # build packed string of enum vals
  strs.sort { |a, b| b.size <=> a.size }.reduce('') do |r, k|
    r.index(k) ? r : (r + k)
  end
end

# get namespace from command-line args
NS = ARGV.shift
raise "Usage: #$0 <ns>" unless NS

# read data from stdin
DATA = STDIN.read

# read enums from schema definitions
enums = JSON(DATA)['definitions'].select { |id, row|
  # limit to enumerated string types
  row['type'] == 'string' && row.key?('enum')
}.freeze

# build pack name and pack data
pack = '_pack_%s' % [Digest::SHA256.hexdigest(DATA)[0,32]]
PACK_DATA = to_packed(enums)

puts(T[:main] % {
  # package namespace
  ns: NS,

  # name and data for packed string
  pack: pack,
  pack_data: PACK_DATA,

  enums:  enums.map { |id, row|
    # parse type from ID
    type = Type.new(id)

    vals = row['enum'].map { |val|
      # build enumeration name
      enum_name = T[:enum_name] % {
        type_acronym: type.acronym, 
        name: val.split('_').map { |s|
          s.downcase.capitalize
        }.join,
      }

      {
        pack: pack,
        type: type.title,
        comment: type.comment,
        val: val,
        ofs: PACK_DATA.index(val),
        len: val.size,
        name: enum_name,
      }
    }

    T[:enum] % {
      type: type.title,
      comment: type.comment,
      consts: vals.map { |val| T[:const] % val }.join,
      parse_cases: vals.map { |val| T[:parse_case] % val }.join,
      string_cases: vals.map { |val| T[:string_case] % val }.join,
      unmarshal_cases: vals.map { |val| T[:unmarshal_case] % val }.join,
    }
  }.join("\n"),
})
