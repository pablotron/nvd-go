#!/usr/bin/env ruby
# frozen_string_literal: true

#
# gen-scores.rb: Read vulnerabilities from source path, extract CVSS
# v3.1 vector strings, base scores, and base severities for each
# vulnerability, and write gzip-compressed, JSON-encoded results to
# destination path.
#

# load libraries
require 'json'
require 'zlib'

# paths
BASE_DIR = File.join(__dir__, '../../..')
SRC_PATH = File.join(BASE_DIR, 'nvd-api/testdata/cves-response-2023.json.gz')
DST_PATH = File.join(__dir__, 'v31-scores.json.gz')

# map of test data destination column to source CVSS data column
COL_MAP = {
  vector: 'vectorString',
  score: 'baseScore',
  severity: 'baseSeverity'
}.freeze

#
# convert CVSS data to test data
#
def convert(cvss_data)
  COL_MAP.each_with_object({}) { |(dst, src), r| r[dst] = cvss_data[src] }
end

# read vulnerabilities from source path
VULNS = JSON(Zlib.gunzip(File.read(SRC_PATH)))['vulnerabilities'].freeze

# map vulnerabilities to unique cvss v3.1 vector, score, and severity
ROWS = VULNS.each_with_object([]) do |v, r|
  ms = (v['cve']['metrics']['cvssMetricV31'] || [])
  ms.each { |m| r << convert(m['cvssData']) }
end.uniq

# write compressed, JSON-encoded results to DST_PATH
Zlib::GzipWriter.open(DST_PATH) { |fh| fh << JSON(ROWS) }
