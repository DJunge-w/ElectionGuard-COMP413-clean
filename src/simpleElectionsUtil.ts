// import { CiphertextElectionContext, PlaintextBallot, PlaintextBallotContest, PlaintextBallotSelection, PrivateElectionContext } from "./simple_election_data";
// import { 
//     // ElGamalKeyPair, 
//     elgamal_keypair_from_secret } from "./elgamal";
// import { elements_mod_q, elements_mod_q_no_zero } from "./groupUtils";
// import { ElementModP, ElementModQ, ONE_MOD_Q, TWO_MOD_Q } from "./group";
// // import { strictEqual } from "assert";

// const __presidents = [
//     "George Washington",
//     "John Adams",
//     "Thomas Jefferson",
//     "James Madison",
//     "James Monroe",
//     "John Quincy Adams",
//     "Andrew Jackson",
//     "Martin Van Buren",
//     "William Henry Harrison",
//     "John Tyler",
//     "James K. Polk",
//     "Zachary Taylor",
//     "Millard Fillmore",
//     "Franklin Pierce",
//     "James Buchanan",
//     "Abraham Lincoln",
//     "Andrew Johnson",
//     "Ulysses S. Grant",
//     "Rutherford B. Hayes",
//     "James Garfield",
//     "Chester Arthur",
//     "Grover Cleveland",
//     "Benjamin Harrison",
//     "Grover Cleveland",
//     "William McKinley",
//     "Theodore Roosevelt",
//     "William Howard Taft",
//     "Woodrow Wilson",
//     "Warren G. Harding",
//     "Calvin Coolidge",
//     "Herbert Hoover",
//     "Franklin D. Roosevelt",
//     "Harry S. Truman",
//     "Dwight Eisenhower",
//     "John F. Kennedy",
//     "Lyndon B. Johnson",
//     "Richard Nixon",
//     "Gerald Ford",
//     "Jimmy Carter",
//     "Ronald Reagan",
//     "George Bush",
//     "Bill Clinton",
//     "George W. Bush",
//     "Barack Obama",
//     "Donald Trump",
//     "Joe Biden",
// ];

// ///////// Utility functions that are used by simple_elections_test /////////

// // Generates a tuple of a PrivateElectionContext and a list of well-formed PlaintextBallots.
// // If the number of candidates is 0, then it will be drawn at random from a large set.
// export function context_and_ballots(num_ballots: number, num_candidates = 3): [CiphertextElectionContext, PlaintextBallot[]] {
//     if (num_candidates <= 0) {
//         num_candidates = getRandomNumberInclusive(2, __presidents.length);
//     }
        
//     const context = election_contexts(num_candidates);
//     const ballots = plaintext_ballots(context, num_ballots);
//     return [context, ballots];
// }

// // Generates a tuple of a PrivateElectionContext and a list of PlaintextBallots, some
// // of which might not be well-formed.
// export function context_and_arbitrary_ballots(num_ballots: number, num_candidates = 3): [CiphertextElectionContext, PlaintextBallot[]] {
//     if (num_candidates <= 0) {
//         num_candidates = getRandomNumberInclusive(2, __presidents.length);
//     }
        
//     const context = election_contexts(num_candidates);
//     const ballots = plaintext_arbitrary_ballots(context, num_ballots);
//     return [context, ballots];
// }

// // Generates a list of the requested number of ballots. Some will be well-formed
// // and others might have overvotes.
// export function plaintext_arbitrary_ballots(context: CiphertextElectionContext, num_ballots: number): PlaintextBallot[] {
//     let ballots: PlaintextBallot[] = [];
//     for (let i = 0; i < num_ballots; i++) {
//         ballots = [...ballots, plaintext_arbitrary_ballot(context, "ballot" + formatNumberLength(i, 3), 3)];
//     }
//     return ballots;
// }

// // Generates a plaintext ballot, might be well-formed or might be an overvote.
// // :param context: An election context, with the necessary crypto keys, etc.
// // :param ballot_id: A string to use for this ballot's identifier.
// export function plaintext_arbitrary_ballot(context: CiphertextElectionContext, ballot_id: string, num_names:number): PlaintextBallot {
//     // const num_names = context.names.length;
//     let selections: PlaintextBallotSelection[] = [];
//     for (let i = 0; i < num_names; i++) {
//         selections = [...selections, new PlaintextBallotSelection("aritrary-candidate-" + i, getRandomNumberInclusive(0, 1))];
//     }
//     const contest = [new PlaintextBallotContest(selections)];
//     //to use: 'some-unique-ballot-id-123',
//     return new PlaintextBallot( ballot_id, contest);
// }

// // Generates a `PrivateElectionContext` for an election with the
// // given number of candidates.
// // :param num_candidates: Desired number of candidates for the election.
// export function election_contexts(num_candidates: number): CiphertextElectionContext {
//     const e = elements_mod_q_no_zero();
//     const keypair = elgamal_keypair_from_secret(e.notEqual(ONE_MOD_Q) ? e : TWO_MOD_Q);
//     const base_hash = elements_mod_q();
//     return new CiphertextElectionContext(
//         1, 1, new ElementModP(BigInt('11621479678980606145')), 
//         new ElementModQ(BigInt(2)), 
//         new ElementModQ(BigInt('19846')), 
//         new ElementModQ(BigInt('16545')),
//         new ElementModQ(BigInt(62667)),null);
// }

// // Generates a list of the requested number of ballots. All will be well-formed.
// export function plaintext_ballots(context: CiphertextElectionContext, num_ballots: number): PlaintextBallot[] {
//     let ballots: PlaintextBallot[] = [];
//     for (let i = 0; i < num_ballots; i++) {
//         // placeholder of num_names
//         ballots = [...ballots, plaintext_ballot(context, "ballot" + formatNumberLength(i, 3), 3)];
//     }
//     return ballots;
// }

// // Generates a plaintext ballot, which might be blank or might have at most one vote
// // for a candidate.
// // :param context: An election context, with the necessary crypto keys, etc.
// // :param ballot_id: A string to use for this ballot's identifier.
// export function plaintext_ballot(context: CiphertextElectionContext, ballot_id: string, num_names:number): PlaintextBallot {
//     // -1 means we select nobody, otherwise we select the nth candidate
//     // const num_names = context.names.length;
//     const choice = getRandomNumberInclusive(-1, num_names - 1);
//     let selections: PlaintextBallotSelection[] = [];
//     for (let i = 0; i < num_names; i++) {
//         selections = [...selections, new PlaintextBallotSelection("aritrary-candidate-" + i, choice === i ? 1 : 0)];
//     }
//     const contest = [new PlaintextBallotContest(selections)];
//     // to use 'some-unique-ballot-id-123', 
//     return new PlaintextBallot(ballot_id, contest);
// }

// // A string formatter for formatting ballot number,
// // achieve the same functionality as f"ballot{i:03d}" in python where i is a variable
// // Code taken from: https://stackoverflow.com/questions/1127905/how-can-i-format-an-integer-to-a-specific-length-in-javascript
// export function formatNumberLength(num: number, length: number): string {
//     let r = "" + num;
//     while (r.length < length) {
//         r = "0" + r;
//     }
//     return r;
// }

// /**
//  * Returns a random integer between min (inclusive) and max (inclusive).
//  * The value is no lower than min (or the next integer greater than min
//  * if min isn't an integer) and no greater than max (or the next integer
//  * lower than max if max isn't an integer).
//  * Using Math.round() will give you a non-uniform distribution!
//  * Code taken from: https://stackoverflow.com/questions/1527803/generating-random-whole-numbers-in-javascript-in-a-specific-range
//  */
// export function getRandomNumberInclusive(min: number, max: number): number {
//     min = Math.ceil(min);
//     max = Math.floor(max);
//     return Math.floor(Math.random() * (max - min + 1)) + min;
// }
