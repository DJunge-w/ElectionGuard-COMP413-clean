import fc from 'fast-check';
import seedrandom from 'seedrandom';
import {
  ElectionContext,
  ElGamalKeypair,
  GroupContext,
  PlaintextBallot,
  PlaintextContest,
  EncryptionState,
} from '../../../src/electionguard';
import * as M from '../../../src/electionguard/ballot/manifest';
import {selectionFrom} from '../../../src/electionguard/ballot/plaintext-ballot';
import {
  chunkArray,
  numberRange,
  shuffleArray,
  zipMap4,
} from '../../../src/electionguard/core/utils';
import {
  arrayIndexedArbitrary,
  elementModQNoZero,
  elGamalKeypair,
} from '../core/generators';

const _first_names = [
  'James',
  'Mary',
  'John',
  'Patricia',
  'Robert',
  'Jennifer',
  'Michael',
  'Linda',
  'William',
  'Elizabeth',
  'David',
  'Barbara',
  'Richard',
  'Susan',
  'Joseph',
  'Jessica',
  'Thomas',
  'Sarah',
  'Charles',
  'Karen',
  'Christopher',
  'Nancy',
  'Daniel',
  'Margaret',
  'Matthew',
  'Lisa',
  'Anthony',
  'Betty',
  'Donald',
  'Dorothy',
  'Sylvia',
  'Viktor',
  'Camille',
  'Mirai',
  'Anant',
  'Rohan',
  'François',
  'Altuğ',
  'Sigurður',
  'Böðmóður',
  'Quang Dũng',
];

const _last_names = [
  'SMITH',
  'JOHNSON',
  'WILLIAMS',
  'JONES',
  'BROWN',
  'DAVIS',
  'MILLER',
  'WILSON',
  'MOORE',
  'TAYLOR',
  'ANDERSON',
  'THOMAS',
  'JACKSON',
  'WHITE',
  'HARRIS',
  'MARTIN',
  'THOMPSON',
  'GARCIA',
  'MARTINEZ',
  'ROBINSON',
  'CLARK',
  'RODRIGUEZ',
  'LEWIS',
  'LEE',
  'WALKER',
  'HALL',
  'ALLEN',
  'YOUNG',
  'HERNANDEZ',
  'KING',
  'WRIGHT',
  'LOPEZ',
  'HILL',
  'SCOTT',
  'GREEN',
  'ADAMS',
  'BAKER',
  'GONZALEZ',
  'STEELE-LOY',
  "O'CONNOR",
  'ANAND',
  'PATEL',
  'GUPTA',
  'ĐẶNG',
];

export function humanName(): fc.Arbitrary<string> {
  return fc
    .tuple(fc.constantFrom(..._first_names), fc.constantFrom(..._last_names))
    .map(t => {
      const [firstName, lastName] = t;
      return `${firstName} ${lastName}`;
    });
}

export function twoLetterCode(): fc.Arbitrary<string> {
  return fc.stringOf(
    fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('')),
    {minLength: 2, maxLength: 2}
  );
}

export function language(
  context: GroupContext
): fc.Arbitrary<M.ManifestLanguage> {
  return fc.tuple(fc.emailAddress(), twoLetterCode()).map(t => {
    const [email, language] = t;
    return new M.ManifestLanguage(context, email, language);
  });
}

export function languageHumanName(
  context: GroupContext
): fc.Arbitrary<M.ManifestLanguage> {
  return fc.tuple(humanName(), twoLetterCode()).map(t => {
    const [name, language] = t;
    return new M.ManifestLanguage(context, name, language);
  });
}

export function emailAnnotatedString(
  context: GroupContext
): fc.Arbitrary<M.ManifestAnnotatedString> {
  return fc.tuple(twoLetterCode(), fc.emailAddress()).map(t => {
    const [language, email] = t;
    return new M.ManifestAnnotatedString(context, language, email);
  });
}

export function internationalizedText(
  context: GroupContext
): fc.Arbitrary<M.ManifestInternationalizedText> {
  return fc.array(language(context), {minLength: 1, maxLength: 3}).map(t => {
    return new M.ManifestInternationalizedText(context, t);
  });
}

export function internationalizedHumanName(
  context: GroupContext
): fc.Arbitrary<M.ManifestInternationalizedText> {
  return fc
    .array(languageHumanName(context), {minLength: 1, maxLength: 3})
    .map(t => {
      return new M.ManifestInternationalizedText(context, t);
    });
}

export function annotatedString(
  context: GroupContext
): fc.Arbitrary<M.ManifestAnnotatedString> {
  return language(context).map(t => {
    return new M.ManifestAnnotatedString(context, t.language, t.value);
  });
}

export function electionType(): fc.Arbitrary<M.ManifestElectionType> {
  return fc
    .constantFrom(...M.ManifestElectionTypeStrings)
    .filter(t => t !== 'unknown');
}

export function reportingUnitType(): fc.Arbitrary<M.ManifestReportingUnitType> {
  return fc
    .constantFrom(...M.ManifestReportingUnitTypeStrings)
    .filter(t => t !== 'unknown');
}

export function voteVariationType(): fc.Arbitrary<M.ManifestVoteVariationType> {
  return fc
    .constantFrom(...M.ManifestVoteVariationTypeStrings)
    .filter(t => t !== 'unknown');
}

export function contactInformation(
  context: GroupContext
): fc.Arbitrary<M.ManifestContactInformation> {
  return fc
    .tuple(
      optional(fc.array(fc.string())),
      optional(fc.array(emailAnnotatedString(context))),
      optional(fc.array(annotatedString(context))),
      optional(humanName())
    )
    .map(t => {
      const [address, email, phone, name] = t;
      return new M.ManifestContactInformation(
        context,
        address,
        email,
        phone,
        name
      );
    });
}

export function stringToInternational(
  context: GroupContext,
  input: string
): M.ManifestInternationalizedText {
  return new M.ManifestInternationalizedText(context, [
    new M.ManifestLanguage(context, input, 'EN'),
  ]);
}

export function ballotStyle(
  context: GroupContext,
  parties: Array<M.ManifestParty>,
  geoUnits: Array<M.ManifestGeopoliticalUnit>
): fc.Arbitrary<M.ManifestBallotStyle> {
  if (parties.length === 0 || geoUnits.length === 0) {
    throw new Error('non-zero length inputs required for ballotStyle');
  }
  const gpUnitIds = geoUnits.map(t => t.objectId);
  const partyIds = parties.map(t => t.objectId);

  return fc.tuple(optional(fc.webUrl()), fc.uuid()).map(t => {
    const [url, uuid] = t;
    return new M.ManifestBallotStyle(context, uuid, gpUnitIds, partyIds, url);
  });
}

export function ballotStyles(
  context: GroupContext,
  parties: Array<M.ManifestParty>,
  geoUnits: Array<M.ManifestGeopoliticalUnit>
): fc.Arbitrary<Array<M.ManifestBallotStyle>> {
  if (parties.length === 0 || geoUnits.length === 0) {
    throw new Error('non-zero length inputs required for ballotStyles');
  }
  const maxNumBallotStyles = Math.min(parties.length, geoUnits.length);
  return fc
    .integer({min: 1, max: maxNumBallotStyles})
    .chain(numBallotStyles => {
      return fc
        .tuple(
          fc.uniqueArray(fc.uuid(), {
            minLength: numBallotStyles,
            maxLength: numBallotStyles,
          }),
          fc.array(fc.webUrl(), {
            minLength: numBallotStyles,
            maxLength: numBallotStyles,
          })
        )
        .map(([uuids, urls]) => {
          const partySets = chunkArray(parties, numBallotStyles);
          const geoUnitSets = chunkArray(geoUnits, numBallotStyles);
          return zipMap4(
            uuids,
            geoUnitSets,
            partySets,
            urls,
            (uuid, gs, ps, url) =>
              new M.ManifestBallotStyle(
                context,
                uuid,
                gs.map(g => g.objectId),
                ps.map(p => p.objectId),
                url
              )
          );
        });
    });
}

export function partyLists(
  context: GroupContext,
  numParties: number
): fc.Arbitrary<Array<M.ManifestParty>> {
  if (numParties <= 0) {
    throw new Error('numParties must be > 0');
  }

  const partyNames = numberRange(1, numParties).map(t => `Party${t}`);
  const partyAbbrvs = numberRange(1, numParties).map(t => `P${t}`);

  return fc
    .tuple(
      fc.uniqueArray(fc.uuid(), {minLength: numParties, maxLength: numParties}),
      fc.array(optional(fc.webUrl()), {
        minLength: numParties,
        maxLength: numParties,
      })
    )
    .map(t => {
      const [uuids, urls] = t;
      return zipMap4(
        uuids,
        urls,
        partyNames,
        partyAbbrvs,
        (uuid, url, partyName, partyAbbrv) =>
          new M.ManifestParty(
            context,
            uuid,
            stringToInternational(context, partyName),
            partyAbbrv,
            undefined,
            url
          )
      );
    });
}

export function geopoliticalUnit(
  context: GroupContext
): fc.Arbitrary<M.ManifestGeopoliticalUnit> {
  return fc
    .tuple(
      fc.uuid(),
      fc.string(),
      reportingUnitType(),
      optional(contactInformation(context))
    )
    .map(t => {
      const [uuid, name, reportingType, contactInfo] = t;
      return new M.ManifestGeopoliticalUnit(
        context,
        uuid,
        name,
        reportingType,
        contactInfo
      );
    });
}

export function candidate(
  context: GroupContext,
  partyList: Array<M.ManifestParty> | undefined
): fc.Arbitrary<M.ManifestCandidate> {
  const pidArb =
    partyList !== undefined && partyList.length > 0
      ? fc.constantFrom(...partyList).map(p => p.partyId)
      : fc.constant(undefined);

  return fc
    .tuple(
      fc.uuid(),
      optional(internationalizedHumanName(context)),
      optional(pidArb),
      optional(fc.webUrl())
    )
    .map(t => {
      const [uuid, name, partyId, url] = t;
      return new M.ManifestCandidate(context, uuid, name, partyId, url, false);
    });
}

function candidateToSelectionDescription(
  context: GroupContext,
  candidate: M.ManifestCandidate,
  sequenceOrder: number
): M.ManifestSelectionDescription {
  return new M.ManifestSelectionDescription(
    context,
    `c-${candidate.candidateId}`,
    sequenceOrder,
    candidate.candidateId
  );
}

interface CandidatesAndContestDescription {
  candidates: Array<M.ManifestCandidate>;
  contestDescription:
    | M.ManifestCandidateContestDescription
    | M.ManifestReferendumContestDescription;
}

export function candidateContestDescription(
  context: GroupContext,
  sequenceOrder: number,
  partyList: Array<M.ManifestParty>,
  geoUnits: Array<M.ManifestGeopoliticalUnit>,
  n: number | undefined = undefined,
  m: number | undefined = undefined
): fc.Arbitrary<CandidatesAndContestDescription> {
  const nArb = n === undefined ? fc.integer({min: 1, max: 3}) : fc.constant(n);

  return nArb.chain(nFinal => {
    const mArb =
      m === undefined
        ? fc.integer({min: 0, max: 3}).map(m => nFinal + m)
        : fc.constant(m);

    return mArb.chain(mFinal => {
      const partyIds = partyList.map(it => it.partyId);

      return fc
        .array(candidate(context, partyList), {
          minLength: mFinal,
          maxLength: mFinal,
        })
        .chain(contestCandidates => {
          const selectionDescriptions = contestCandidates.map((candidate, i) =>
            candidateToSelectionDescription(context, candidate, i + 1)
          );

          const voteVariation = nFinal === 1 ? 'one_of_m' : 'n_of_m';

          return fc
            .tuple(
              fc.uuid(),
              fc.constantFrom(...geoUnits).map(it => it.objectId),
              fc.string(),
              optional(internationalizedText(context)),
              optional(internationalizedText(context))
            )
            .map(t => {
              const [
                uuid,
                electoralDistrictId,
                name,
                ballotTitle,
                ballotSubtitle,
              ] = t;
              return {
                candidates: contestCandidates,
                contestDescription: new M.ManifestCandidateContestDescription(
                  context,
                  uuid,
                  sequenceOrder,
                  electoralDistrictId,
                  voteVariation,
                  nFinal,
                  mFinal,
                  name,
                  selectionDescriptions,
                  ballotTitle,
                  ballotSubtitle,
                  partyIds // TODO: make this also optional
                ),
              };
            });
        });
    });
  });
}

export function candidateContestDescriptionRoomForOvervoting(
  context: GroupContext,
  sequenceOrder: number,
  partyList: Array<M.ManifestParty>,
  geoUnits: Array<M.ManifestGeopoliticalUnit>
): fc.Arbitrary<CandidatesAndContestDescription> {
  return fc
    .integer({min: 1, max: 3})
    .chain(n =>
      fc
        .integer({min: 1, max: 3})
        .chain(m =>
          candidateContestDescription(
            context,
            sequenceOrder,
            partyList,
            geoUnits,
            n,
            n + m
          )
        )
    );
}

export function referendumContestDescription(
  context: GroupContext,
  sequenceOrder: number,
  geoUnits: Array<M.ManifestGeopoliticalUnit>
): fc.Arbitrary<CandidatesAndContestDescription> {
  return fc.integer({min: 1, max: 3}).chain(n => {
    return fc
      .array(candidate(context, undefined), {minLength: n, maxLength: n})
      .chain(contestCandidates => {
        const selectionDescriptions = contestCandidates.map((candidate, i) =>
          candidateToSelectionDescription(context, candidate, i)
        );
        return fc
          .tuple(
            fc.uuid(),
            fc.constantFrom(...geoUnits).map(it => it.objectId),
            fc.string(),
            optional(internationalizedText(context)),
            optional(internationalizedText(context))
          )
          .map(t => {
            const [
              uuid,
              electoralDistrictId,
              name,
              ballotTitle,
              ballotSubTitle,
            ] = t;
            return {
              candidates: contestCandidates,
              contestDescription: new M.ManifestReferendumContestDescription(
                context,
                uuid,
                sequenceOrder,
                electoralDistrictId,
                'one_of_m',
                1,
                n,
                name,
                selectionDescriptions,
                ballotTitle,
                ballotSubTitle
              ),
            };
          });
      });
  });
}

export function contestDescription(
  context: GroupContext,
  sequenceOrder: number,
  partyList: Array<M.ManifestParty>,
  geoUnits: Array<M.ManifestGeopoliticalUnit>
): fc.Arbitrary<CandidatesAndContestDescription> {
  return fc.oneof(
    candidateContestDescription(context, sequenceOrder, partyList, geoUnits),
    referendumContestDescription(context, sequenceOrder, geoUnits)
  );
}

export function electionDescription(
  context: GroupContext,
  maxNumParties = 3,
  maxNumGeopoliticalUnits = 3,
  maxNumContests = 3
): fc.Arbitrary<M.Manifest> {
  if (
    maxNumParties <= 0 ||
    maxNumGeopoliticalUnits <= 0 ||
    maxNumContests <= 0
  ) {
    throw new Error(
      'must have at least one party, one contest, and one geopolitical unit'
    );
  }

  return fc
    .tuple(
      fc.integer({min: 1, max: maxNumParties}),
      fc.integer({min: 1, max: maxNumGeopoliticalUnits}),
      fc.integer({min: 1, max: maxNumContests})
    )
    .chain(t => {
      const [numParties, numGeopoliticalUnits, numContests] = t;
      return fc
        .tuple(
          partyLists(context, numParties),
          fc.uniqueArray(geopoliticalUnit(context), {
            minLength: numGeopoliticalUnits,
            maxLength: numGeopoliticalUnits,
          })
        )
        .chain(([parties, geoUnits]) =>
          fc
            .tuple(
              ballotStyles(context, parties, geoUnits),
              electionType(),
              fc.date(),
              fc.emailAddress(),
              optional(internationalizedText(context)),
              optional(contactInformation(context)),
              arrayIndexedArbitrary(
                i => contestDescription(context, i + 1, parties, geoUnits),
                numContests
              )
            )
            .map(t => {
              const [
                styles,
                type,
                date,
                scopeId,
                electionName,
                contactInfo,
                candidateContests,
              ] = t;
              const candidates = candidateContests.flatMap(c => c.candidates);
              const contests = candidateContests.map(c => c.contestDescription);

              return new M.Manifest(
                context,
                `electionScopeId/${scopeId}`,
                '1.02',
                type,
                date.toISOString(),
                date.toISOString(),
                geoUnits,
                parties,
                candidates,
                contests,
                styles,
                electionName,
                contactInfo
              );
            })
        );
    });
}

export function plaintextVotedBallot(manifest: M.Manifest) {
  if (manifest.ballotStyles === undefined || manifest.ballotStyles.length < 1) {
    throw new Error('need at least one ballot style');
  }

  return fc
    .constantFrom(...manifest.ballotStyles)
    .filter(bs => manifest.getContests(bs.ballotStyleId).length >= 1)
    .chain(ballotStyle => {
      return fc.tuple(fc.uuid(), fc.string()).map(t => {
        const [ballotUuid, rngSeed] = t;
        const contests = manifest.getContests(ballotStyle.ballotStyleId);
        const rng = seedrandom(rngSeed);

        const votedContests = contests.map(contest => {
          if (!contest.isValid()) {
            throw new Error(`contest isn't valid?: ${contest}`);
          }
          const n = contest.numberElected;
          const ballotSelections = contest.selections;
          const randomSelections = shuffleArray(ballotSelections, rng);
          const cutPoint = rng.int32() % n;
          const yesVotes = randomSelections.slice(0, cutPoint);
          const noVotes = randomSelections.slice(cutPoint);
          const noVotesSubset = noVotes.slice(
            0,
            rng.int32() % (noVotes.length + 1)
          );

          const votedSelections = yesVotes
            .map(selectionDesc =>
              selectionFrom(selectionDesc.selectionId, false, true)
            )
            .concat(
              noVotesSubset.map(selectionDesc =>
                selectionFrom(selectionDesc.selectionId, false, false)
              )
            );
          return new PlaintextContest(
            contest.contestId,
            shuffleArray(votedSelections, rng)
          );
        });

        return new PlaintextBallot(
          ballotUuid,
          ballotStyle.ballotStyleId,
          votedContests // already shuffled
        );
      });
    });
}

export function plaintextVotedBallots(
  manifest: M.Manifest,
  count = 1
): fc.Arbitrary<Array<PlaintextBallot>> {
  return fc.array(plaintextVotedBallot(manifest), {
    minLength: count,
    maxLength: count,
  });
}

interface CiphertextElectionsTuple {
  keypair: ElGamalKeypair;
  electionContext: ElectionContext;
}

/** Generates a `CiphertextElectionContext` with a single public-private key pair as the encryption context. */
export function ciphertextElection(
  context: GroupContext,
  manifest: M.Manifest
): fc.Arbitrary<CiphertextElectionsTuple> {
  return fc
    .tuple(elGamalKeypair(context), elementModQNoZero(context))
    .map(t => {
      const [keypair, commitmentHash] = t;
      return {
        keypair: keypair,
        electionContext: ElectionContext.create(
          1,
          1,
          keypair.publicKey,
          commitmentHash,
          manifest.cryptoHashElement
        ),
      };
    });
}

export function encryptionState(
  context: GroupContext
): fc.Arbitrary<EncryptionState> {
  return electionDescription(context).chain(manifest => {
    return fc
      .tuple(ciphertextElection(context, manifest))
      .map(([{electionContext}]) => {
        return new EncryptionState(context, manifest, electionContext, true);
      });
  });
}

interface ElectionAndBallots {
  manifest: M.Manifest;
  ballots: Array<PlaintextBallot>;
  keypair: ElGamalKeypair;
  electionContext: ElectionContext;
}

/**
 * A convenience generator to generate all of the necessary components for simulating an election.
 * Every ballot will match the same ballot style.
 */
export function electionAndBallots(
  context: GroupContext,
  numBallots = 3
): fc.Arbitrary<ElectionAndBallots> {
  if (numBallots < 1) {
    throw new Error(`numBallots must be at least one: ${numBallots}`);
  }

  return electionDescription(context).chain(manifest => {
    return fc
      .tuple(
        ciphertextElection(context, manifest),
        plaintextVotedBallots(manifest, numBallots)
      )
      .map(t => {
        const [cec, ballots] = t;

        return {
          manifest: manifest,
          ballots: ballots,
          keypair: cec.keypair,
          electionContext: cec.electionContext,
        };
      });
  });
}

function optional<T>(x: fc.Arbitrary<T>): fc.Arbitrary<T | undefined> {
  return fc.option(x, {nil: undefined});
}
