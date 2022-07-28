import {
  ElectionObjectBase,
  matchingArraysOfAnyElectionObjects,
} from './election-object-base';
import {Manifest, ManifestContestDescription} from './manifest';
import {associateBy} from '../core/utils';

/**
 * The plaintext representation of a voter's ballot selections for all the contests in an election.
 * The ballotId is a unique Ballot ID created by the external system. This is used both as input,
 * and for the roundtrip: input -> encrypt -> decrypt -> output.
 */
export class PlaintextBallot implements ElectionObjectBase {
  constructor(
    readonly ballotId: string, // a unique ballot ID created by the external system
    readonly ballotStyleId: string, // matches BallotStyle.ballotStyleId
    readonly contests: Array<PlaintextContest>
  ) {}
  get objectId(): string {
    return this.ballotId;
  }

  normalize(manifest: Manifest) {
    return new PlaintextBallot(
      this.ballotId,
      this.ballotStyleId,
      this.contests.map(contest => {
        const mcontest = manifest.getContest(contest.contestId);
        if (mcontest === undefined)
          throw new Error(`Extraneous contest: ${contest.contestId}`);

        return contest.normalize(mcontest);
      })
    );
  }

  equals(other: PlaintextBallot): boolean {
    return (
      other instanceof PlaintextBallot &&
      other.ballotId === this.ballotId &&
      other.ballotStyleId === this.ballotStyleId &&
      matchingArraysOfAnyElectionObjects(other.contests, this.contests)
    );
  }
}

/** The plaintext representation of a voter's selections for one contest. */
export class PlaintextContest implements ElectionObjectBase {
  constructor(
    readonly contestId: string, // matches ContestDescription.contestId
    readonly selections: Array<PlaintextSelection> = []
  ) {}

  get objectId(): string {
    return this.contestId;
  }

  normalize(description: ManifestContestDescription) {
    const pselections = associateBy(this.selections, s => s.selectionId);

    const normalizedSelections = description.selections.map(s => {
      const match = pselections.get(s.selectionId);
      // if no selection was made, we explicitly set it to false
      if (match === undefined)
        return selectionFrom(s.selectionId, false, false);

      return new PlaintextSelection(
        match.selectionId,
        match.vote,
        match.isPlaceholderSelection,
        match.writeIn
      );
    });

    return new PlaintextContest(this.contestId, normalizedSelections);
  }

  equals(other: PlaintextContest): boolean {
    return (
      other instanceof PlaintextContest &&
      other.contestId === this.contestId &&
      matchingArraysOfAnyElectionObjects(other.selections, this.selections)
    );
  }
}

/** The plaintext representation of one selection for a particular contest. */
export class PlaintextSelection implements ElectionObjectBase {
  constructor(
    readonly selectionId: string, // matches SelectionDescription.selectionId
    readonly vote: number,
    readonly isPlaceholderSelection: boolean = false,
    readonly writeIn?: string
  ) {}

  get objectId(): string {
    return this.selectionId;
  }

  equals(other: PlaintextSelection): boolean {
    return (
      other instanceof PlaintextSelection &&
      other.selectionId === this.selectionId &&
      other.vote === this.vote &&
      other.isPlaceholderSelection === this.isPlaceholderSelection &&
      other.writeIn === this.writeIn
    );
  }
}

export function selectionFrom(
  selectionId: string,
  isPlaceholder: boolean,
  isAffirmative: boolean
): PlaintextSelection {
  return new PlaintextSelection(
    selectionId,
    isAffirmative ? 1 : 0,
    isPlaceholder,
    undefined // no extended data
  );
}
