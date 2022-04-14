const eg = require('../../../dist/tsc/API/APIUtils.js');
const ds = require('../../../dist/tsc/API/typical_ballot_data.js')
const ballot = require('./minimal/plaintext_ballot_ballot-85c8f918-73fc-11ec-9daf-acde48001122.json');
const manifest = require('./minimal/manifest.json');

const realManifest = eg.buildManifest(manifest);
const realBallot = eg.buildBallot(ballot);
const result = eg.encryptBallot(realBallot, realManifest);
  if (result instanceof ds.ErrorBallotInput) {
    console.log("error input!")
  }

console.log("encrypted ballot's hash: ", result.hash);
console.log("encrypted ballot's seed: ", result.seed);
