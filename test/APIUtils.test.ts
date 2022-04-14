import {buildBallot, buildManifest, encryptBallot} from "../src/API/APIUtils";
import {ErrorBallotInput} from "../src/API/typical_ballot_data";
import fs from 'fs';
import path from "path";

const testFolder = `src/API/test/minimal`;
const ballotPath = path.join(testFolder, "plaintext_ballot_ballot-85c8f918-73fc-11ec-9daf-acde48001122.json");
const ballotFile = fs.readFileSync(ballotPath, "utf8");
const manifestPath = path.join(testFolder, "manifest.json");
const manifestFile = fs.readFileSync(manifestPath, "utf8");

describe("TestAPI", () => {
  test("build Manifest Ballot and encrypt", () => {
    const ballot = JSON.parse(ballotFile);
    const manifest = JSON.parse(manifestFile);
    const realManifest = buildManifest(manifest);
    const realBallot = buildBallot(ballot);
    const result = encryptBallot(realBallot, realManifest);
    if (result instanceof ErrorBallotInput) {
      console.log("error input!")
    }

    if (!(result instanceof ErrorBallotInput)) {
      console.log("encrypted ballot's hash: ", result.hash);
      console.log("encrypted ballot's seed: ", result.seed);
    }
    
  });
});


