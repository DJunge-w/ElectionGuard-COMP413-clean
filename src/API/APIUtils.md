# API Documentation

- ## Usage

  - All ElectionGuard Typescript code are inside out.js file.

  - To encrypt a ballot in JSON, there are three steps

    - 1. Call **buildBallot**(ballot) where ballot is in JSON. This function returns a Ballot class data.
      2. Call **buildManifest**(ballot) where ballot is in JSON. This function returns a Manifest class data.
      3. Call **encryptBallot**(build_ballot, manifest) where build_ballot: Ballot and manifest: Manifest. This function returns either EncryptBallotOutput or ErrorBallotInput upon errors. EncryptBallotOutput has two attributes, hash and seed. 

    - A sample usage is here

    - ```typescript
      import * as ballot from './AaronBallot/super_complex_ballot.json';
      
      const realBallot = buildBallot(ballot);
      const realManifest = buildManifest(ballot);
      const result = encryptBallot(realBallot, realManifest);
        if (result instanceof ErrorBallotInput) {
          console.log("error input!")
          return;
        }
      
      console.log("encrypted ballot's hash: ", result.hash);
      console.log("encrypted ballot's seed: ", result.seed);
      ```

