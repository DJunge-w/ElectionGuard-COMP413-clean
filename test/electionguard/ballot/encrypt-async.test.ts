import fc from 'fast-check';
import {
  BallotState,
  bigIntContext4096,
  eitherRightOrFail,
  getCoreCodecsForContext,
  encryptBallot,
  EncryptionState,
  AsyncBallotEncryptor,
  getBallotCodecsForContext,
} from '../../../src/electionguard';
import {normalizeBallot} from '../../../src/electionguard/ballot/plaintext-ballot';
// import * as log from '../../../src/electionguard/core/logging';
import {elementModQ, fcFastConfig} from '../core/generators';
import {electionAndBallots} from './generators';

// we support the 3072 and 4096-bit contexts, but we're going
// to test with the bigger context, since it's likely to be
// how we're deployed.
const groupContext = bigIntContext4096();

describe('Async encryption wrapper', () => {
  afterAll(() => {
    // console.info('After-action report for async-encryption:');
    // log.consoleAllLogs();
  });

  test('Encrypt conventionally & with async; identical result', async () => {
    await fc.assert(
      fc.asyncProperty(
        electionAndBallots(groupContext, 1),
        elementModQ(groupContext),
        elementModQ(groupContext),
        async (eb, prev, seed) => {
          const timestamp = Math.floor(Date.now() / 1000);
          const encryptionState = new EncryptionState(
            groupContext,
            eb.manifest,
            eb.electionContext,
            true
          );

          // log.info('encrypt-async-test', 'starting conventional encryption');
          for (const plaintextBallot of eb.ballots) {
            const normalizedBallot = normalizeBallot(
              plaintextBallot,
              eb.manifest
            );

            const encryptedBallot = encryptBallot(
              encryptionState,
              normalizedBallot,
              prev,
              seed,
              timestamp
            );

            const bCodecs = getBallotCodecsForContext(groupContext);
            const cCodecs = getCoreCodecsForContext(groupContext);

            const manifestJson = bCodecs.manifestCodec.encode(
              eb.manifest
            ) as object;
            const electionContextJson = cCodecs.electionContextCodec.encode(
              eb.electionContext
            ) as object;

            /* const manifestDecoded = */ eitherRightOrFail(
              bCodecs.manifestCodec.decode(manifestJson)
            );
            const electionContextDecoded = eitherRightOrFail(
              cCodecs.electionContextCodec.decode(electionContextJson)
            );

            expect(
              electionContextDecoded.jointPublicKey.element.isValidResidue()
            ).toBe(true);

            // log.info('encrypt-async-test', 'initializing async encryption');
            const asyncEncryptor = AsyncBallotEncryptor.create(
              groupContext,
              manifestJson,
              electionContextJson,
              true,
              normalizedBallot.ballotStyleId,
              normalizedBallot.ballotId,
              prev,
              seed,
              timestamp
            );

            // log.info('encrypt-async-test', 'launching async encryption');
            // launches encryption on each contest: note the absence of return values
            normalizedBallot.contests.forEach(contest =>
              asyncEncryptor.encrypt(contest)
            );

            const encryptedBallot2 = await asyncEncryptor.getEncryptedBallot();
            // log.info('encrypt-async-test', 'async tasks complete');

            expect(encryptedBallot.equals(encryptedBallot2)).toBe(true);

            // now, fetch the result from the serialized version and compare
            const encryptedBallot3 =
              await asyncEncryptor.getSerializedEncryptedBallot();

            const deserializedSubmittedBallot = eitherRightOrFail(
              bCodecs.submittedBallotCodec.decode(
                encryptedBallot3.serializedEncryptedBallot
              )
            );

            expect(
              deserializedSubmittedBallot.equals(
                encryptedBallot2.submit(BallotState.CAST)
              )
            ).toBe(true);
          }
        }
      ),
      fcFastConfig
    );
  });

  test.todo('incompatible contexts');
});
