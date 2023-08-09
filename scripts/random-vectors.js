#!/usr/bin/node
"use strict";

//
// random-vectors.js: Generate 1000 random CVSS v3.1 vector strings,
// calculate their metric scores (base, temporal, and environmental)
// using the script from the NIST NVD calculator, then write the
// results to standard output as a JSON array.
//
// Each row of the JSON array contains 4 elements:
//
// - vector string
// - base score
// - temporal score
// - environmental score
//

// load cvss 3.1 calculator
const CVSS31 = require('./cvsscalc31.js').CVSS31;

// number of vectors to generate
const NUM_VECTORS = 1000;

// generate random cvss v3.1 vector string
const random_vector = (() => {
  // CVSS v3.x metrics keys and possible character values
  const METRICS = [
    { id: 'AV', cs: 'NALP' },
    { id: 'AC', cs: 'LH' },
    { id: 'PR', cs: 'NLH' },
    { id: 'UI', cs: 'NR' },
    { id: 'S', cs: 'UC' },
    { id: 'C', cs: 'NLH' },
    { id: 'I', cs: 'NLH' },
    { id: 'A', cs: 'NLH' },
    { id: 'E', cs: 'XUPFH' },
    { id: 'RL', cs: 'XOTWU' },
    { id: 'RC', cs: 'XURC' },
    { id: 'CR', cs: 'XLMH' },
    { id: 'IR', cs: 'XLMH' },
    { id: 'AR', cs: 'XLMH' },
    { id: 'MAV', cs: 'XNALP' },
    { id: 'MAC', cs: 'XLH' },
    { id: 'MPR', cs: 'XNLH' },
    { id: 'MUI', cs: 'XNR' },
    { id: 'MS', cs: 'XUC' },
    { id: 'MC', cs: 'XNLH' },
    { id: 'MI', cs: 'XNLH' },
    { id: 'MA', cs: 'XNLH' },
  ];

  // pick random element of array
  const pick = (a) => a[Math.floor(Math.random() * a.length)];

  // metric template
  const T = ({id,cs}) => `${id}:${pick(cs.split(''))}`;
  return () => ('CVSS:3.1/' + METRICS.map(T).join('/'));
})();

// create an array of N random vector strings
const random_vectors = (n) => Array(n).fill(0).map(random_vector);

// convert scores to row
const to_row = (() => {
  // columns from calculateCVSSFromVector() output to keep
  const COLS = [
    'vectorString',
    'baseMetricScore',
    'temporalMetricScore',
    'environmentalMetricScore',
  ];

  return (row) => COLS.map(col => row[col]);
})();

// generate random vectors, calculate their scores, extract relevant
// columns, JSON-encode them, write the results to standard output
process.stdout.write(JSON.stringify(random_vectors(NUM_VECTORS).map(
  v => to_row(CVSS31.calculateCVSSFromVector(v))
)));
