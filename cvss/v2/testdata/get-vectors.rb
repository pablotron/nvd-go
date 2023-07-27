#!/usr/bin/env ruby
# frozen_string_literal: true

#
# get-vectors.rb: Read vulnerabilities from source path, extract CVSS
# v3.1 vector strings, and write tests to standard output.
#

# load libraries
require 'json'
require 'zlib'

# paths
BASE_DIR = File.join(__dir__, '../../..')
SRC_PATH = File.join(BASE_DIR, 'nvd-api/testdata/cves-response-1999.json.gz')

# row template
T = %{{ "%<vector>s", []Metric { %<metrics>s } },}

#
# convert CVSS data to test data
#
def convert(v)
  { vector: v, metrics: v.split('/').map { |m| m.gsub(/:/, '_') }.join(', ') }
end

# read vulnerabilities from source path
VULNS = JSON(Zlib.gunzip(File.read(SRC_PATH)))['vulnerabilities'].freeze

# map vulnerabilities to unique vectors and metrics
ROWS = VULNS.each_with_object([]) do |v, r|
  ms = (v['cve']['metrics']['cvssMetricV2'] || [])
  ms.each { |m| r << convert(m['cvssData']['vectorString']) }
end.uniq

puts(ROWS.map { |row| T % row })
