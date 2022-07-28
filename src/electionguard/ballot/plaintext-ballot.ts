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

/**
 * Returns a new ballot with contests corresponding to every contest in the given manifest.
 * Puts contests full of non-affirmative selections in place of missing contests.
 * All contests on the returned ballot are themselves normalized.
 *
 * If the given ballot has contests or selections that don't correspond to any on the ballot,
 * an error is thrown.
 */
export function normalizeBallot(
  ballot: PlaintextBallot,
  manifest: Manifest
): PlaintextBallot {
  const pcontests = associateBy(ballot.contests, c => c.contestId);
  const contestsForStyle = manifest.getContests(ballot.ballotStyleId);
  const contestsForStyleIds = contestsForStyle.map(c => c.contestId);

  for (const pcontest of ballot.contests) {
    if (!contestsForStyleIds.includes(pcontest.contestId))
      throw new Error(`Ballot has extraneous contest: ${pcontest.contestId}`);
  }

  const normalizedContests = contestsForStyle.map(mcontest => {
    const pcontest = pcontests.get(mcontest.contestId);
    // if this contest is absent, we create a new one with just placeholders
    if (pcontest === undefined) return contestFrom(mcontest);

    return normalizeContest(pcontest, mcontest);
  });

  return new PlaintextBallot(
    ballot.ballotId,
    ballot.ballotStyleId,
    normalizedContests
  );
}

/**
 * Returns a new contest with as many selections as the given contest description.
 * Puts non-affirmative selections in place of missing selections.
 *
 * If the contest has selections that don't correspond to any selection in the description,
 * an error is thrown.
 */
export function normalizeContest(
  contest: PlaintextContest,
  description: ManifestContestDescription
): PlaintextContest {
  const pselections = associateBy(contest.selections, s => s.selectionId);
  const descriptionSelectionIds = description.selections.map(
    s => s.selectionId
  );

  for (const pselection of contest.selections) {
    if (!descriptionSelectionIds.includes(pselection.selectionId))
      throw new Error(
        `Contest has extraneous selection: ${pselection.selectionId}`
      );
  }

  const normalizedSelections = description.selections.map(mselection => {
    const pselection = pselections.get(mselection.selectionId);
    // if no selection was made, we explicitly set it to a non-affirmative vote
    if (pselection === undefined)
      return new PlaintextSelection(mselection.selectionId, 0, false);

    return new PlaintextSelection(
      pselection.selectionId,
      pselection.vote,
      pselection.isPlaceholderSelection,
      pselection.writeIn
    );
  });

  return new PlaintextContest(contest.contestId, normalizedSelections);
}

/** Returns a contest full of non-affirmative selections for the given description. */
function contestFrom(mcontest: ManifestContestDescription): PlaintextContest {
  const selections = mcontest.selections.map(it =>
    selectionFrom(it.selectionId, false, false)
  );
  return new PlaintextContest(mcontest.contestId, selections);
}

/** Returns a selection */
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
