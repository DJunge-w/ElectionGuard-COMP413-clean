import {ElectionContext} from '../core/constants';
import {ElementModQ, GroupContext} from '../core/group-common';
import {hashElements} from '../core/hash';
import {eitherRightOrFail, getCoreCodecsForContext} from '../core/json';
import {mapFrom, stringSetsEqual} from '../core/utils';
import {CiphertextBallot, CiphertextContest} from './ciphertext-ballot';
import {sortedArrayOfOrderedElectionObjects} from './election-object-base';
import {encryptContest, EncryptionState} from './encrypt';
import {getBallotCodecsForContext} from './json';
import {Manifest, ManifestContestDescription} from './manifest';
import {PlaintextContest} from './plaintext-ballot';
import * as log from '../core/logging';

/**
 * This class wraps all the state and machinery necessary to offload encryption
 * computations on a contest-by-contest basis. The idea is that you initialize
 * it with all the state it will ever need as well as specifying the particular
 * ballot style. Then, you can call encrypt(), which will immediately
 * return while running the computation in a webworker or equivalent.
 *
 * If you encrypt the same contest twice, the latter one will replace the
 * earlier one.
 *
 * When you're done, you call getEncryptedBallot(), which will block until
 * all the contest encryption is complete, and will then return the encrypted
 * ballot. This call has the potential to fail, for example, if you haven't
 * encrypted all the necessary contests for the given ballot style.
 *
 * Also of note: while elsewhere in the ElectionGuard-Python codebase, errors
 * are indicated by returning undefined, here it's different. Errors are indicated
 * by throwing an Error class, which will contain enough context to assist
 * in tracking down any problems.
 */
export class AsyncBallotEncryptor {
  readonly encryptionState: EncryptionState;
  readonly manifestContests: Map<string, ManifestContestDescription>;
  readonly sequenceOrderMap: Map<string, number>;
  readonly contestIds: string[];
  readonly encryptedContests: Map<string, Promise<CiphertextContest>>;
  readonly ballotNonce: ElementModQ;

  /**
   * Builds an instance of AsyncBallotEncryptor with good default values
   * when appropriate.
   * @param group GroupContext for all mathematical operations
   * @param manifestObj A JavaScript object corresponding to an ElectionGuard Manifest.
   * @param electionContextObj A JavaScript object corresponding to an ElectionGuard ElectionContext.
   * @param validate Specifies whether each encryption is validated immediately
   *   after it is created. Significant performance penalty, but might catch
   *   one-in-a-million hardware failures on unreliable clients.
   * @param ballotStyleId The manifest might specify multiple ballot styles. This
   *   names the ballot style to be used for this particular ballot.
   * @param ballotId Every ballot needs a string identifier which should be globally
   *   unique.
   * @param ballotNonce The root of all randomness used for encrypting the ballot. If
   *  not provided, a new random number will be securely generated.
   * @param timestamp Optional timestamp for the ballot, in seconds since the Unix epoch.
   *   If not provided, the current time will be used (Date.now() / 1000) when the
   *   final ballot is completed and returned.
   */
  static create(
    group: GroupContext,
    manifestObj: object,
    electionContextObj: object,
    validate: boolean,
    ballotStyleId: string,
    ballotId: string,
    ballotNonce?: ElementModQ,
    timestamp?: number
  ): AsyncBallotEncryptor {
    const bCodecs = getBallotCodecsForContext(group);
    const cCodecs = getCoreCodecsForContext(group);

    log.info('encrypt-async.create', 'about to decode inputs');
    const manifest = eitherRightOrFail(
      bCodecs.manifestCodec.decode(manifestObj)
    );

    log.info('encrypt-async.create', 'manifest decoded');
    const electionContext = eitherRightOrFail(
      cCodecs.electionContextCodec.decode(electionContextObj)
    );
    log.info('encrypt-async.create', 'electionContext decoded');

    if (ballotNonce === undefined) ballotNonce = group.randQ();

    return new AsyncBallotEncryptor(
      manifest,
      electionContext,
      validate,
      group,
      ballotNonce,
      ballotStyleId,
      ballotId,
      timestamp
    );
  }

  /**
   * Builds an instance of AsyncBallotEncryptor. For ease
   * of use, you may prefer the static create() method instead,
   * which allows you to pass in JavaScript objects for external
   * types like the manifest, and it will let you know if there's
   * a problem.
   * @param manifest Defines everything about the election contests, candidates, etc.
   * @param electionContext Defines everything about the election cryptographic settings.
   * @param validate Specifies whether each encryption is validated immediately
   *   after it is created. Significant performance penalty, but might catch
   *   one-in-a-million hardware failures on unreliable clients.
   * @param group GroupContext for all mathematical operations
   * @param masterNonce The root of all randomness used for encrypting the ballot.
   * @param ballotStyleId The manifest might specify multiple ballot styles. This
   *   names the ballot style to be used for this particular ballot.
   * @param ballotId Every ballot needs a string identifier which should be globally
   *   unique.
   * @param timestamp Optional timestamp for the ballot, in seconds since the Unix epoch.
   *   If not provided, the current time will be used (Date.now() / 1000) when the
   *   final ballot is completed and returned.
   */
  constructor(
    manifest: Manifest,
    electionContext: ElectionContext,
    validate: boolean,
    readonly group: GroupContext,
    readonly masterNonce: ElementModQ,
    readonly ballotStyleId: string,
    readonly ballotId: string,
    readonly timestamp?: number
  ) {
    this.encryptionState = new EncryptionState(
      masterNonce.context,
      manifest,
      electionContext,
      validate
    );

    // This copies some code in encryptBallot(); the ballotNonce is
    // hashed deeper as we go.
    this.ballotNonce = hashElements(
      group,
      this.encryptionState.manifestHash,
      ballotId,
      masterNonce
    );

    const manifestContestDescriptions = manifest.getContests(ballotStyleId);

    this.contestIds = manifestContestDescriptions.map(mcd => mcd.contestId);

    this.manifestContests = mapFrom(
      manifestContestDescriptions,
      mcd => mcd.contestId,
      mcd => mcd
    );

    this.sequenceOrderMap = mapFrom(
      manifestContestDescriptions,
      mcd => mcd.contestId,
      mcd => mcd.sequenceOrder
    );
    this.encryptedContests = new Map(); // to be filled in later
  }

  /** Starts an async encryption of the contest. Returns immediately. */
  encrypt(contest: PlaintextContest): void {
    const sequenceOrder = this.sequenceOrderMap.get(contest.contestId);
    const manifestContestDesc = this.manifestContests.get(contest.contestId);

    if (sequenceOrder !== contest.sequenceOrder) {
      log.warn(
        'encrypt-async',
        `unexpected seequence order: ${sequenceOrder} vs. ${contest.sequenceOrder}`
      );
    }

    if (manifestContestDesc === undefined || sequenceOrder === undefined) {
      log.errorAndThrow(
        'encrypt-async',
        `unexpected absence of a ManifestContestDescription for ${contest.contestId}`
      );
    }

    if (manifestContestDesc.contestId !== contest.contestId) {
      log.errorAndThrow(
        'encrypt-async',
        `unexpected contestId mismatch between manifest and plaintext (${manifestContestDesc.contestId} vs. ${contest.contestId})`
      );
    }

    this.encryptedContests.set(
      contest.contestId,
      this.encryptHelper(contest, sequenceOrder, manifestContestDesc)
    );
  }

  // TODO: replace this async stuff with calls out to workerpool
  private async encryptHelper(
    contest: PlaintextContest,
    sequenceOrder: number,
    manifestContestDesc: ManifestContestDescription
  ): Promise<CiphertextContest> {
    // Privacy note: don't log the entire contest because we don't
    // want voter preferences to end up on the JavaScript console.

    log.info(
      'encrypt-async.encryptHelper',
      `encrypting contest ${contest.contestId}, sequence #${sequenceOrder}`
    );

    if (sequenceOrder !== contest.sequenceOrder) {
      log.errorAndThrow(
        'encrypt-async.encryptHelper',
        `wrong sequence number: ${contest.sequenceOrder} vs. ${sequenceOrder}`
      );
    }

    return encryptContest(
      this.encryptionState,
      contest,
      this.ballotId,
      manifestContestDesc,
      this.ballotNonce
    );
  }

  /**
   * Fetches the encrypted ballot, possibly blocking until all the async
   * computation is complete. If a contest wasn't submitted, then it's
   * not possible to derive the result, so an Error is thrown.
   */
  async getEncryptedBallot(): Promise<CiphertextBallot> {
    if (
      !stringSetsEqual(
        Array.from(this.encryptedContests.keys()),
        this.contestIds
      )
    ) {
      log.errorAndThrow(
        'AsyncBallotEncryptor.getEncryptedBallot',
        `missing contests: only ${this.encryptedContests.size} of ${this.contestIds.length} present`
      );
    }

    // If we get here, we've got all the promises we're going to need,
    // so now we just have to make sure they're all done.

    const promisedResults = Promise.all(this.encryptedContests.values()).catch(
      e => {
        // hopefully, if something goes wrong, this will notice it and log something
        log.warn(
          'AsyncBallotEncryptor.getEncryptedBallot',
          `promise failure? ${e}`
        );
        throw e;
      }
    );

    const unsortedEncryptedContests = await promisedResults;

    const encryptedContests = sortedArrayOfOrderedElectionObjects(
      unsortedEncryptedContests
    );

    const cryptoHash = hashElements(
      this.encryptionState.group,
      this.ballotId,
      this.encryptionState.manifestHash,
      encryptedContests
    );

    const timestamp =
      this.timestamp === undefined ? Date.now() / 1000 : this.timestamp;

    const ballotCode = hashElements(
      this.encryptionState.group,
      this.encryptionState.group.ZERO_MOD_Q, // tracking hash of prior ballot
      timestamp,
      cryptoHash
    );

    const encryptedBallot = new CiphertextBallot(
      this.ballotId,
      this.ballotStyleId,
      this.encryptionState.manifestHash,
      this.encryptionState.group.ZERO_MOD_Q, // tracking hash of prior ballot
      ballotCode,
      encryptedContests,
      timestamp,
      cryptoHash,
      this.ballotNonce
    );

    return encryptedBallot;
  }
}
