import { ElGamalKeyPair, elgamal_keypair_from_secret } from "../elgamal";
import { add_q, ElementModQ, ONE_MOD_Q, TWO_MOD_Q } from "../group";
import { elements_mod_q, elements_mod_q_no_zero } from "../groupUtils";
import { encrypt_ballot, encrypt_ballots } from "../simple_elections";
import { CiphertextBallot, PlaintextBallot, PlaintextBallotContest, PlaintextBallotSelection, PrivateElectionContext } from "../simple_election_data";
import { get_optional } from "../utils";
import { Ballot, BallotItem, BallotOption, EncryptBallotOutput, ErrorBallotInput, ErrorType} from "./typical_ballot_data";
import {QRCode, ErrorCorrectLevel} from "qrcode-generator-ts";

/**
 * Ballot ==> Whole Election 
 * BallotItem ==> A single question on the ballot
 * BallotOption ==> A single option on a question
 */

// Entry point of the API, give a Ballot item, return the seed and the hash
// Return an ErrorBallotInput in case some fields that are required in encryption in Ballot is missing
export function encryptBallot(inputBallot: Ballot): EncryptBallotOutput | ErrorBallotInput {
    // TODO: First check if the ballot has all the fields we need
    // let validatedBallot = validateBallot(inputBallot);
    // if (validatedBallot instanceof ErrorBallotInput) return validatedBallot;
    const ballot = ballot2PlainTextBallot(inputBallot);
    const context = ballot2Context(inputBallot); 
    const seed_nonce:ElementModQ = elements_mod_q_no_zero();
    const encrypted_ballot: CiphertextBallot = get_optional(encrypt_ballot(context, ballot, seed_nonce));
    return new EncryptBallotOutput(seed_nonce.elem.toString(), encrypted_ballot.crypto_hash_with(seed_nonce).toString());
}

export function getQRCode(strs:string[]):any {
    let qr = new QRCode();
    // size difference found over here: https://snyk.io/advisor/npm-package/qr-code-typescript
    qr.setTypeNumber(8);
    qr.setErrorCorrectLevel(ErrorCorrectLevel.L);
    strs.forEach((str) => qr.addData(str));
    qr.make();

    let img = document.createElement('img');
    img.setAttribute('src', qr.toDataURL() );

    return img;
}

export function ballot2PlainTextBallot(ballot: Ballot): PlaintextBallot {
    let ballotContests: PlaintextBallotContest[] = [];
    ballot.ballotItems.forEach((ballotItem) => {
        ballotContests = [...ballotContests, ballotItem2PlainTextBallotContest(ballotItem)];
    });

    return new PlaintextBallot(ballot.id, ballotContests);
}

export function ballotItem2PlainTextBallotContest(ballotItem: BallotItem): PlaintextBallotContest {
    const selections: PlaintextBallotSelection[] = ballotItem2Selection(ballotItem);
    return new PlaintextBallotContest(selections);
}

export function ballotItem2Selection(ballotItem: BallotItem): PlaintextBallotSelection[] {
    let plainTextSelections: PlaintextBallotSelection[] = [];
    ballotItem.ballotOptions.forEach((ballotOption) => {
        // MISSING: Candidate name from ballotOption
        // what would be the correct field for the selection? Ours assume a candidate name
        plainTextSelections = [...plainTextSelections, new PlaintextBallotSelection(ballotOption.title[0].text, ballotOption.selected === true? 1 : 0)]
    });
    return plainTextSelections;
}

export function ballot2Context(ballot: Ballot): PrivateElectionContext {

    // construct the names list for candidates from ballot
    const names: Set<string> = new Set();
    ballot.ballotItems.forEach((ballotItem) => {
        ballotItem.ballotOptions.forEach((ballotOption) => names.add(ballotOption.title[0].text));
    });
    const namesArr = [...names.values()];
    const e:ElementModQ = elements_mod_q_no_zero();
    const keypair:ElGamalKeyPair = get_optional(elgamal_keypair_from_secret(e.notEqual(ONE_MOD_Q) ? e : TWO_MOD_Q));
    const base_hash:ElementModQ = elements_mod_q();

    return new PrivateElectionContext(ballot.electionName[0].text, namesArr, keypair, base_hash);
}




export function ballot2JSON(ballots: PlaintextBallot[], context: PrivateElectionContext) : any {

    // Is type any safe
    const seed_nonce:ElementModQ = elements_mod_q_no_zero();
    const encrypted_ballots: CiphertextBallot[] = get_optional(encrypt_ballots(context, ballots, seed_nonce));
    let final_hash = new ElementModQ(0n);
    encrypted_ballots.forEach(eBallot => {
        final_hash = add_q(final_hash, eBallot.crypto_hash_with(seed_nonce));
    });

    return JSON.parse(JSON.stringify({seed: seed_nonce.elem.toString(), hash: final_hash.elem.toString()}));
}


export function buildBallot(ballot): Ballot {
    let contests:BallotItem[] = [];
    for(let i = 0; i < ballot.ballotItems.length; i++) {
        let ballotOptions: BallotOption[] = [];
        for(let j = 0; j < ballot.ballotItems[i].ballotOptions.length; j++) {
            const ballotOption = new BallotOption(ballot.ballotItems[i].ballotOptions[j].title[0].text, ballot.ballotItems[i].ballotOptions[j].selected);
            ballotOptions = [...ballotOptions, ballotOption];
        }
        const contest: BallotItem = new BallotItem(ballotOptions);
        contests = [...contests, contest];
    }
    const electionBallot = new Ballot(ballot.id, ballot.electionName[0].text, contests);

    return electionBallot;
}


// Only used for testing
export function buildFakeBallot(): Ballot {
    const names = ['James Miller', 'Liam Garcia','Olivia Brown','Charlotte Li', 'Ava Nguyen', 'Mizu Sawa', 'Park Shu', 'Van Darkholme', 'Wang Jo Jo', 'Ted Budd'];

    // build a fake ballot item
    let ballotOptions1: BallotOption[] = [];
    let ballotOptions2: BallotOption[] = [];
    names.forEach((name, idx) => {
        if (idx < names.length / 2) {
            const ballotOption = new BallotOption(name, false);
            // console.log("ballot1 ballotoptions ", ballotOptions1);
            ballotOptions1 = [...ballotOptions1, ballotOption];
        } else {
            const ballotOption = new BallotOption(name, false);
            ballotOptions2 = [...ballotOptions2, ballotOption];
        }
    });
    const contest1 = new BallotItem(ballotOptions1);
    const contest2 = new BallotItem(ballotOptions2);
    // hard code the selected options, the second contest doesn't select anything
    contest1.ballotOptions[0].selected = true;
    

    // add ballotItem to electionBallot
    // build a ballot
    const electionBallot = new Ballot("001", "firstTest", [contest1, contest2]);
    console.log("the current ballot is ", electionBallot);
    return electionBallot;
}

export function buildLargeFakeBallot(count: number): Ballot {

    const names = ['James Miller', 'Liam Garcia', 'Olivia Brown', 'Charlotte Li', 'Ava Nguyen', 'Mizu Sawa', 'Park Shu', 'Van Darkholme', 'Wang Jo Jo', 'Ted Budd'];
    const contests: BallotItem[] = [];
    for (let i = 0; i < count; i++) {
        let ballotOptions1: BallotOption[] = [];
        names.forEach((name) => {
            const ballotOption = new BallotOption(name, false);
            // console.log("ballot1 ballotoptions ", ballotOptions1);
            ballotOptions1 = [...ballotOptions1, ballotOption];
        });
        const contest1 = new BallotItem(ballotOptions1);
        contests.push(contest1);
    }

    // add ballotItem to electionBallot
    // build a ballot
    const electionBallot = new Ballot("001", "firstTest", contests);

    console.log("the current ballot is ", electionBallot);

    return electionBallot;
}
export function validateBallot(ballot: Ballot): ErrorBallotInput | null {
    if (ballot.electionName === undefined || ballot.electionName.length === 0) return new ErrorBallotInput(ErrorType.MissingElectionName, "Missing Election Name");
    if (ballot.partyId === undefined) return new ErrorBallotInput(ErrorType.MissingBallotPartyId, "Missing Ballot Party ID");
    if (ballot.partyName === undefined || ballot.partyName.length === 0) return new ErrorBallotInput(ErrorType.MissingBallotPartyName, "Missing Ballot Party Name");
    if (ballot.precinctName === undefined || ballot.partyName.length === 0) return new ErrorBallotInput(ErrorType.MissingPrecinctName, "Missing Precinct Name");
    if (ballot.precinctId === undefined) return new ErrorBallotInput(ErrorType.MissingPrecintId, "Missing Precint ID");
    if (ballot.id === undefined) return new ErrorBallotInput(ErrorType.MissingBallotId, "Missing Ballot ID");
    if (ballot.ballotItems === undefined || ballot.ballotItems.length === 0) return new ErrorBallotInput(ErrorType.MissingBallotItems, "Missing BallotItems");
    
    ballot.ballotItems.forEach((ballotItem) => {
        if (ballotItem.ballotOptions === undefined || ballotItem.ballotOptions.length === 0) return new ErrorBallotInput(ErrorType.MissingBallotOptions, "Missing BallotOptions");
        ballotItem.ballotOptions.forEach((ballotOption) => {
            if (ballotOption.candidateId === undefined) return new ErrorBallotInput(ErrorType.MissingCandidateId, "Missing Candidate Id");
            if (ballotOption.title === undefined || ballotOption.title.length === 0) return new ErrorBallotInput(ErrorType.MissingCandidateName, "Missing Candidate Name");
            if (ballotOption.partyId === undefined) return new ErrorBallotInput(ErrorType.MissingCandidatePartyId, "Missing Candidate Party ID");
            if (ballotOption.partyName === undefined || ballotOption.partyName.length === 0) return new ErrorBallotInput(ErrorType.MissingCandidatePartyName, "Missing Candidate Party Name");
        });
    });

    return null;
}
