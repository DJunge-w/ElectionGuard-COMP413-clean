import {
  ConstantChaumPedersenProofKnownNonce,
  DisjunctiveChaumPedersenProofKnownNonce,
} from '../core/chaum-pedersen';
import {ElGamalCiphertext} from '../core/elgamal';
import {ElementModQ} from '../core/group-common';
import {CryptoHashableElement, hashElements} from '../core/hash';
import {HashedElGamalCiphertext} from '../core/hashed-elgamal';
import {
  ElectionObjectBase,
  OrderedObjectBase,
  matchingArraysOfOrderedElectionObjects,
  objEqualsOrUndefEquals,
} from './election-object-base';
import {
  BallotState,
  SubmittedBallot,
  SubmittedContest,
  SubmittedSelection,
} from './submitted-ballot';

/**
 * Represents an encrypted ballot, notably including all of the
 * original encryption nonces. Use the submit() method to convert
 * to a {@link SubmittedBallot} suitable for serialization.
 */
export class CiphertextBallot implements ElectionObjectBase {
  constructor(
    readonly ballotId: string,
    readonly ballotStyleId: string,
    readonly manifestHash: ElementModQ, // matches Manifest.cryptoHash
    readonly codeSeed: ElementModQ,
    readonly code: ElementModQ,
    readonly contests: Array<CiphertextContest>,
    readonly timestamp: number,
    readonly cryptoHash: ElementModQ,
    readonly nonce: ElementModQ
  ) {}

  get objectId(): string {
    return this.ballotId;
  }
  equals(other: CiphertextBallot): boolean {
    return (
      other instanceof CiphertextBallot &&
      other.ballotId === this.ballotId &&
      other.ballotStyleId === this.ballotStyleId &&
      other.manifestHash.equals(this.manifestHash) &&
      other.codeSeed.equals(this.codeSeed) &&
      other.code.equals(this.code) &&
      matchingArraysOfOrderedElectionObjects(other.contests, this.contests) &&
      other.timestamp === this.timestamp &&
      other.cryptoHash.equals(this.cryptoHash) &&
      other.nonce.equals(this.nonce)
    );
  }

  hashedBallotNonce(): ElementModQ {
    return hashElements(
      this.nonce.context,
      this.manifestHash,
      this.ballotId,
      this.nonce
    );
  }

  submit(state: BallotState): SubmittedBallot {
    return new SubmittedBallot(
      this.ballotId,
      this.ballotStyleId,
      this.manifestHash,
      this.codeSeed,
      this.code,
      this.contests.map(v => v.submit()),
      this.timestamp,
      this.cryptoHash,
      state
    );
  }
}

export class CiphertextContest
  implements CryptoHashableElement, OrderedObjectBase
{
  constructor(
    readonly contestId: string, // matches ContestDescription.contestIdd
    readonly sequenceOrder: number, // matches ContestDescription.sequenceOrder
    readonly contestHash: ElementModQ, // matches ContestDescription.cryptoHash
    readonly selections: Array<CiphertextSelection>,
    readonly ciphertextAccumulation: ElGamalCiphertext,
    readonly cryptoHash: ElementModQ,
    readonly proof: ConstantChaumPedersenProofKnownNonce,
    readonly contestNonce: ElementModQ,
    readonly extendedData?: HashedElGamalCiphertext
  ) {}

  get objectId(): string {
    return this.contestId;
  }

  equals(other: CiphertextContest): boolean {
    return (
      other instanceof CiphertextContest &&
      other.contestId === this.contestId &&
      other.contestHash.equals(this.contestHash) &&
      matchingArraysOfOrderedElectionObjects(
        other.selections,
        this.selections
      ) &&
      other.ciphertextAccumulation.equals(this.ciphertextAccumulation) &&
      other.proof.equals(this.proof) &&
      other.contestNonce.equals(this.contestNonce)
    );
    // ignoring extended data
  }

  get cryptoHashElement(): ElementModQ {
    return this.cryptoHash;
  }

  submit(): SubmittedContest {
    return new SubmittedContest(
      this.contestId,
      this.sequenceOrder,
      this.contestHash,
      this.selections.map(v => v.submit()),
      this.ciphertextAccumulation,
      this.cryptoHash,
      this.proof
    );
  }
}

export class CiphertextSelection
  implements CryptoHashableElement, OrderedObjectBase
{
  constructor(
    readonly selectionId: string, // matches SelectionDescription.selectionId
    readonly sequenceOrder: number, // matches SelectionDescription.sequenceOrder
    readonly selectionHash: ElementModQ, // matches SelectionDescription.cryptoHash
    readonly ciphertext: ElGamalCiphertext,
    readonly cryptoHash: ElementModQ,
    readonly isPlaceholderSelection: boolean,
    readonly proof: DisjunctiveChaumPedersenProofKnownNonce,
    readonly selectionNonce?: ElementModQ
  ) {}

  get objectId(): string {
    return this.selectionId;
  }

  equals(other: CiphertextSelection): boolean {
    return (
      other instanceof CiphertextSelection &&
      other.selectionId === this.selectionId &&
      other.sequenceOrder === this.sequenceOrder &&
      other.selectionHash.equals(this.selectionHash) &&
      other.ciphertext.equals(this.ciphertext) &&
      other.cryptoHash.equals(this.cryptoHash) &&
      other.isPlaceholderSelection === this.isPlaceholderSelection &&
      other.proof.equals(this.proof) &&
      objEqualsOrUndefEquals(other.selectionNonce, this.selectionNonce)
    );
  }

  get cryptoHashElement(): ElementModQ {
    return this.cryptoHash;
  }

  submit(): SubmittedSelection {
    return new SubmittedSelection(
      this.selectionId,
      this.sequenceOrder,
      this.selectionHash,
      this.ciphertext,
      this.cryptoHash,
      this.isPlaceholderSelection,
      this.proof
    );
  }
}
