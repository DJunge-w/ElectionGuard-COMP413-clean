import { AnyElectionContext, PlaintextBallot, PlaintextSelection, PrivateElectionContext } from "./simple_election_data";
import { ElGamalKeyPair, elgamal_keypair_from_secret } from "./elgamal";
import { elements_mod_q, elements_mod_q_no_zero } from "./groupUtils";
import { ONE_MOD_Q, TWO_MOD_Q } from "./group";

const __presidents = [
    "George Washington",
    "John Adams",
    "Thomas Jefferson",
    "James Madison",
    "James Monroe",
    "John Quincy Adams",
    "Andrew Jackson",
    "Martin Van Buren",
    "William Henry Harrison",
    "John Tyler",
    "James K. Polk",
    "Zachary Taylor",
    "Millard Fillmore",
    "Franklin Pierce",
    "James Buchanan",
    "Abraham Lincoln",
    "Andrew Johnson",
    "Ulysses S. Grant",
    "Rutherford B. Hayes",
    "James Garfield",
    "Chester Arthur",
    "Grover Cleveland",
    "Benjamin Harrison",
    "Grover Cleveland",
    "William McKinley",
    "Theodore Roosevelt",
    "William Howard Taft",
    "Woodrow Wilson",
    "Warren G. Harding",
    "Calvin Coolidge",
    "Herbert Hoover",
    "Franklin D. Roosevelt",
    "Harry S. Truman",
    "Dwight Eisenhower",
    "John F. Kennedy",
    "Lyndon B. Johnson",
    "Richard Nixon",
    "Gerald Ford",
    "Jimmy Carter",
    "Ronald Reagan",
    "George Bush",
    "Bill Clinton",
    "George W. Bush",
    "Barack Obama",
    "Donald Trump",
    "Joe Biden",
];

///////// Utility functions that are used by simple_elections_test /////////

// Generates a tuple of a PrivateElectionContext and a list of well-formed PlaintextBallots.
// If the number of candidates is 0, then it will be drawn at random from a large set.
export function context_and_ballots(num_ballots: number, num_candidates = 3): [PrivateElectionContext, PlaintextBallot[]] {
    if (num_candidates <= 0) {
        num_candidates = getRandomNumberInclusive(2, __presidents.length);
    }
        
    const context = election_contexts(num_candidates);
    const ballots = plaintext_ballots(context, num_ballots);
    return [context, ballots];
}

// Generates a tuple of a PrivateElectionContext and a list of PlaintextBallots, some
// of which might not be well-formed.
export function context_and_arbitrary_ballots(num_ballots: number, num_candidates = 3): [PrivateElectionContext, PlaintextBallot[]] {
    if (num_candidates <= 0) {
        num_candidates = getRandomNumberInclusive(2, __presidents.length);
    }
        
    const context = election_contexts(num_candidates);
    const ballots = plaintext_arbitrary_ballots(context, num_ballots);
    return [context, ballots];
}

// Generates a list of the requested number of ballots. Some will be well-formed
// and others might have overvotes.
export function plaintext_arbitrary_ballots(context: AnyElectionContext, num_ballots: number): PlaintextBallot[] {
    let ballots: PlaintextBallot[] = [];
    for (let i = 0; i < num_ballots; i++) {
        ballots = [...ballots, plaintext_arbitrary_ballot(context, "ballot" + formatNumberLength(i, 3))];
    }
    return ballots;
}

// Generates a plaintext ballot, might be well-formed or might be an overvote.
// :param context: An election context, with the necessary crypto keys, etc.
// :param ballot_id: A string to use for this ballot's identifier.
export function plaintext_arbitrary_ballot(context: AnyElectionContext, ballot_id: string): PlaintextBallot {
    const num_names = context.names.length;
    let selections: PlaintextSelection[] = [];
    for (let i = 0; i < num_names; i++) {
        selections = [...selections, new PlaintextSelection(context.names[i], getRandomNumberInclusive(0, 1))];
    }

    return new PlaintextBallot(ballot_id, selections);
}

// Generates a `PrivateElectionContext` for an election with the
// given number of candidates.
// :param num_candidates: Desired number of candidates for the election.
export function election_contexts(num_candidates: number): PrivateElectionContext {
    const e = elements_mod_q_no_zero();
    const keypair = elgamal_keypair_from_secret(e.notEqual(ONE_MOD_Q) ? e : TWO_MOD_Q);
    const base_hash = elements_mod_q();
    return new PrivateElectionContext(
        "Test Election", __presidents.slice(0, num_candidates), keypair as ElGamalKeyPair, base_hash
    );
}

// Generates a list of the requested number of ballots. All will be well-formed.
export function plaintext_ballots(context: AnyElectionContext, num_ballots: number): PlaintextBallot[] {
    let ballots: PlaintextBallot[] = [];
    for (let i = 0; i < num_ballots; i++) {
        ballots = [...ballots, plaintext_ballot(context, "ballot" + formatNumberLength(i, 3))];
    }
    return ballots;
}

// Generates a plaintext ballot, which might be blank or might have at most one vote
// for a candidate.
// :param context: An election context, with the necessary crypto keys, etc.
// :param ballot_id: A string to use for this ballot's identifier.
export function plaintext_ballot(context: AnyElectionContext, ballot_id: string): PlaintextBallot {
    // -1 means we select nobody, otherwise we select the nth candidate
    const num_names = context.names.length;
    const choice = getRandomNumberInclusive(-1, num_names - 1);
    let selections: PlaintextSelection[] = [];
    for (let i = 0; i < num_names; i++) {
        selections = [...selections, new PlaintextSelection(context.names[i], choice === i ? 1 : 0)];
    }
    // console.log("selections in plaintext_ballot", selections);
    return new PlaintextBallot(ballot_id, selections);
}

// A string formatter for formatting ballot number,
// achieve the same functionality as f"ballot{i:03d}" in python where i is a variable
// Code taken from: https://stackoverflow.com/questions/1127905/how-can-i-format-an-integer-to-a-specific-length-in-javascript
export function formatNumberLength(num: number, length: number): string {
    let r = "" + num;
    while (r.length < length) {
        r = "0" + r;
    }
    return r;
}

/**
 * Returns a random integer between min (inclusive) and max (inclusive).
 * The value is no lower than min (or the next integer greater than min
 * if min isn't an integer) and no greater than max (or the next integer
 * lower than max if max isn't an integer).
 * Using Math.round() will give you a non-uniform distribution!
 * Code taken from: https://stackoverflow.com/questions/1527803/generating-random-whole-numbers-in-javascript-in-a-specific-range
 */
export function getRandomNumberInclusive(min: number, max: number): number {
    min = Math.ceil(min);
    max = Math.floor(max);
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
