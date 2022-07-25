import fc from 'fast-check';
import {
  BallotState,
  bigIntContext3072,
  eitherRightOrFail,
  getBallotCodecsForContext,
  PlaintextBallot,
  PlaintextContest,
  encryptBallot,
  EncryptionState,
} from '../../../src/electionguard';
import {decryptAndVerifyBallot} from '../../../src/electionguard/ballot/decrypt';
import {matchingArraysOfAnyElectionObjects} from '../../../src/electionguard/ballot/election-object-base';
import {Nonces} from '../../../src/electionguard/core/nonces';
import {shuffleArray} from '../../../src/electionguard/core/utils';
import {elementModQ, fcFastConfig} from '../core/generators';
import {electionAndBallots} from './generators';

const groupContext = bigIntContext3072();
describe('Election / ballot encryption', () => {
  test('Generators yield valid contests', () => {
    fc.assert(
      fc.property(electionAndBallots(groupContext), eb => {
        const contests = eb.manifest.contests;
        const contestsValid = contests.every(c => c.isValid());
        expect(contestsValid).toBe(true);
      }),
      fcFastConfig
    );
  });
  test('Encryption/decryption inverses', () => {
    fc.assert(
      fc.property(
        electionAndBallots(groupContext),
        elementModQ(groupContext),
        elementModQ(groupContext),
        (eb, prev, seed) => {
          const nonces = new Nonces(seed);
          // This ends up running the verification twice: once while encrypting, and once while decrypting.
          // This is fine, because we'd like to catch verification errors at encryption time, if possible,
          // but we'll take them wherever we can get them.

          const encryptionState = new EncryptionState(
            groupContext,
            eb.manifest,
            eb.electionContext,
            true
          );
          const submittedBallots = eb.ballots.map((b, i) =>
            encryptBallot(encryptionState, b, prev, nonces.get(i)).submit(
              BallotState.CAST
            )
          );
          const decryptedBallots = submittedBallots.map(sb =>
            decryptAndVerifyBallot(
              eb.manifest,
              eb.electionContext.cryptoExtendedBaseHash,
              eb.keypair,
              sb
            )
          );

          expect(
            matchingArraysOfAnyElectionObjects(eb.ballots, decryptedBallots)
          ).toBe(true);
        }
      ),
      fcFastConfig
    );
  });
  test('Encryption serialization/deserialization', () => {
    fc.assert(
      fc.property(
        electionAndBallots(groupContext, 1),
        elementModQ(groupContext),
        elementModQ(groupContext),
        (eb, codeSeed, encryptionSeed) => {
          const bCodecs = getBallotCodecsForContext(groupContext);
          const encryptionState = new EncryptionState(
            groupContext,
            eb.manifest,
            eb.electionContext,
            false
          );
          const submittedBallot = encryptBallot(
            encryptionState,
            eb.ballots[0],
            codeSeed,
            encryptionSeed
          ).submit(BallotState.CAST);

          const serializedBallot =
            bCodecs.submittedBallotCodec.encode(submittedBallot);

          const deserializedBallotMaybe =
            bCodecs.submittedBallotCodec.decode(serializedBallot);

          const deserializedBallot = eitherRightOrFail(deserializedBallotMaybe);

          expect(submittedBallot.equals(deserializedBallot)).toBe(true);
        }
      ),
      fcFastConfig
    );
  });
  test('Encrypt the same election twice; idential result', () => {
    fc.assert(
      fc.property(
        electionAndBallots(groupContext),
        elementModQ(groupContext),
        elementModQ(groupContext),
        (eb, prev, seed) => {
          const timestamp = Math.floor(Date.now() / 1000);
          const nonces = new Nonces(seed);

          const encryptionState = new EncryptionState(
            groupContext,
            eb.manifest,
            eb.electionContext,
            false
          );
          const submittedBallots1 = eb.ballots.map((b, i) =>
            encryptBallot(
              encryptionState,
              b,
              prev,
              nonces.get(i),
              timestamp
            ).submit(BallotState.CAST)
          );
          const submittedBallots2 = eb.ballots.map((b, i) =>
            encryptBallot(
              encryptionState,
              b,
              prev,
              nonces.get(i),
              timestamp
            ).submit(BallotState.CAST)
          );
          const matching = matchingArraysOfAnyElectionObjects(
            submittedBallots1,
            submittedBallots2
          );
          expect(matching).toBe(true);
        }
      ),
      fcFastConfig
    );
  });
  test('Encryption nonces are all unique', () => {
    fc.assert(
      fc.property(
        electionAndBallots(groupContext),
        elementModQ(groupContext),
        elementModQ(groupContext),
        (eb, prev, seed) => {
          const nonces = new Nonces(seed);

          const encryptionState = new EncryptionState(
            groupContext,
            eb.manifest,
            eb.electionContext,
            false
          );

          const selectionHashes = eb.manifest.contests.flatMap(contest =>
            contest.selections.map(selection =>
              selection.cryptoHashElement.toBigint()
            )
          );

          expect(noRepeatingBigints(selectionHashes)).toBe(true);

          const encryptedBallots = eb.ballots.map((b, i) =>
            encryptBallot(encryptionState, b, prev, nonces.get(i))
          );

          const elGamalPads = encryptedBallots.flatMap(ballot =>
            ballot.contests.flatMap(contest =>
              contest.selections.map(selection =>
                selection.ciphertext.pad.toBigint()
              )
            )
          );

          expect(noRepeatingBigints(elGamalPads)).toBe(true);

          const selectionNonces: bigint[] = encryptedBallots.flatMap(ballot =>
            ballot.contests.flatMap(contest =>
              contest.selections.map(selection => {
                if (selection.selectionNonce === undefined) {
                  throw new Error('selectionNonce should not be undefined');
                } else {
                  return selection.selectionNonce.toBigint();
                }
              })
            )
          );

          const contestNonces: bigint[] = encryptedBallots.flatMap(ballot =>
            ballot.contests.flatMap(contest => contest.contestNonce.toBigint())
          );

          const ballotNonces: bigint[] = encryptedBallots.map(ballot =>
            ballot.ballotEncryptionSeed.toBigint()
          );

          const allBallotNonces = selectionNonces
            .concat(contestNonces)
            .concat(ballotNonces);

          expect(noRepeatingBigints(allBallotNonces)).toBe(true);

          const chaumPedersenBigintsCR = encryptedBallots.flatMap(ballot =>
            ballot.contests.flatMap(contest =>
              contest.selections.flatMap(selection => [
                selection.proof.proof0.c.toBigint(),
                selection.proof.proof0.r.toBigint(),
                selection.proof.proof1.c.toBigint(),
                selection.proof.proof1.r.toBigint(),
              ])
            )
          );

          const chaumPedersenBigintsA = encryptedBallots.flatMap(ballot =>
            ballot.contests.flatMap(contest =>
              contest.selections.flatMap(selection => [
                selection.proof.proof0.a.toBigint(),
                selection.proof.proof1.a.toBigint(),
              ])
            )
          );

          const chaumPedersenBigintsB = encryptedBallots.flatMap(ballot =>
            ballot.contests.flatMap(contest =>
              contest.selections.flatMap(selection => [
                selection.proof.proof0.b.toBigint(),
                selection.proof.proof1.b.toBigint(),
              ])
            )
          );

          expect(noRepeatingBigints(chaumPedersenBigintsCR)).toBe(true);
          expect(
            noRepeatingBigints(
              chaumPedersenBigintsB.concat(chaumPedersenBigintsA)
            )
          ).toBe(true);

          const absolutelyEverything = elGamalPads
            .concat(allBallotNonces)
            .concat(chaumPedersenBigintsA)
            .concat(chaumPedersenBigintsB)
            .concat(chaumPedersenBigintsCR);

          expect(noRepeatingBigints(absolutelyEverything)).toBe(true);
        }
      ),
      fcFastConfig
    );
  });
  test("Shuffling plaintext doesn't affect ciphertext ballots", () => {
    fc.assert(
      fc.property(
        electionAndBallots(groupContext, 1),
        elementModQ(groupContext),
        elementModQ(groupContext),
        (eb, prev, seed) => {
          const timestamp = Math.floor(Date.now() / 1000);
          const nonces = new Nonces(seed);
          const encryptionState = new EncryptionState(
            groupContext,
            eb.manifest,
            eb.electionContext,
            true
          );

          const [ballot] = eb.ballots;
          const ciphertextBallot = encryptBallot(
            encryptionState,
            ballot,
            prev,
            nonces.get(0),
            timestamp
          );

          const copy = new PlaintextBallot(
            ballot.ballotId,
            ballot.ballotStyleId,
            shuffleArray(
              ballot.contests.map(
                contest =>
                  new PlaintextContest(
                    contest.contestId,
                    shuffleArray(contest.selections)
                  )
              )
            )
          );
          const copyCiphertextBallot = encryptBallot(
            encryptionState,
            copy,
            prev,
            nonces.get(0),
            timestamp
          );

          expect(copyCiphertextBallot.equals(ciphertextBallot)).toBe(true);
        }
      ),
      fcFastConfig
    );
  });
  test('Ballots with missing contests result in errors', () => {
    fc.assert(
      fc.property(
        electionAndBallots(groupContext),
        elementModQ(groupContext),
        elementModQ(groupContext),
        (eb, prev, seed) => {
          const nonces = new Nonces(seed);
          const encryptionState = new EncryptionState(
            groupContext,
            eb.manifest,
            eb.electionContext,
            true
          );
          const ballotsMissingContests = eb.ballots.map(
            ballot =>
              new PlaintextBallot(
                ballot.ballotId,
                ballot.ballotStyleId,
                ballot.contests.slice(1)
              )
          );

          ballotsMissingContests.forEach((b, i) => {
            expect(() =>
              encryptBallot(encryptionState, b, prev, nonces.get(i))
            ).toThrow();
          });
        }
      ),
      fcFastConfig
    );
  });
});

function noRepeatingBigints(input: bigint[]): boolean {
  // We're doing this with bigint rather than elements
  // because we know built-in types work without us having
  // to worry about whether we're doing equality correctly.

  return new Set(input).size === input.length;
}
