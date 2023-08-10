#!/usr/bin/node
"use strict";

//
// random-vectors.js: Generate 1000 random CVSS v3.0 or v3.1 vector strings
// and their base, temporal, and environmental metric scores as
// calculated by the script from the NVD CVSS calculator, then write the
// results to standard output as a JSON array.
//
// Each row of the JSON array contains 4 elements:
//
// - vector string
// - base score
// - temporal score
// - environmental score
//

const VERSIONS = {
  v30: require('./cvsscalc30.js').CVSS,
  v31: require('./cvsscalc31.js').CVSS31,
};

// check command-line
if (process.argv.length != 3 || Object.keys(VERSIONS).indexOf(process.argv[2]) === -1) {
  // print usage, exit with error
  process.stderr.write(`Usage: ${process.argv[0]} [${Object.keys(VERSIONS).join('|')}]`);
  process.exit(-1);
}

// load calculator
const CVSS = VERSIONS[process.argv[2]];

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
  return () => (CVSS.CVSSVersionIdentifier + '/' + METRICS.map(T).join('/'));
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
  v => to_row(CVSS.calculateCVSSFromVector(v))
)));
