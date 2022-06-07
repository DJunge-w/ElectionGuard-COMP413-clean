import {
  ConstantChaumPedersenProofKnownNonce,
  DisjunctiveChaumPedersenProofKnownNonce,
} from '../core/chaum-pedersen';
import {ElGamalCiphertext} from '../core/elgamal';
import {ElementModQ} from '../core/group-common';
import {CryptoHashableElement} from '../core/hash';
import {HashedElGamalCiphertext} from '../core/hashed-elgamal';

export class SubmittedBallot implements CryptoHashableElement {
  constructor(
    readonly ballotId: string,
    readonly ballotStyleId: string,
    readonly manifestHash: ElementModQ, // matches Manifest.cryptoHash
    readonly codeSeed: ElementModQ,
    readonly code: ElementModQ,
    readonly contests: Array<SubmittedContest>,
    readonly timestamp: number,
    readonly cryptoHashElement: ElementModQ,
    readonly state: BallotState
  ) {}
}

export class SubmittedContest implements CryptoHashableElement {
  constructor(
    readonly contestId: string, // matches ContestDescription.contestIdd
    readonly sequenceOrder: number, // matches ContestDescription.sequenceOrderv
    readonly contestHash: ElementModQ, // matches ContestDescription.cryptoHash
    readonly selections: Array<SubmittedSelection>,
    readonly ciphertextAccumulation: ElGamalCiphertext,
    readonly cryptoHashElement: ElementModQ,
    readonly proof: ConstantChaumPedersenProofKnownNonce
  ) {}
}

export class SubmittedSelection implements CryptoHashableElement {
  constructor(
    readonly selectionId: string, // matches SelectionDescription.selectionId
    readonly sequenceOrder: number, // matches SelectionDescription.sequenceOrder
    readonly selectionHash: ElementModQ, // matches SelectionDescription.cryptoHash
    readonly ciphertext: ElGamalCiphertext,
    readonly cryptoHashElement: ElementModQ,
    readonly isPlaceholderSelection: boolean,
    readonly proof: DisjunctiveChaumPedersenProofKnownNonce,
    readonly extendedData?: HashedElGamalCiphertext
  ) {}
}

export enum BallotState {
  /** A ballot that has been explicitly cast */
  CAST,
  /** A ballot that has been explicitly spoiled */
  SPOILED,
  /** A ballot whose state is unknown to ElectionGuard and will not be included in results. */
  UNKNOWN,
}
