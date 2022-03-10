/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
import { DisjunctiveChaumPedersenProof,
    ChaumPedersenDecryptionProof,
    ConstantChaumPedersenProof,
    // make_chaum_pedersen_generic,
    // make_disjunctive_chaum_pedersen_one,
    make_disjunctive_chaum_pedersen,
    make_constant_chaum_pedersen,
    } from "./chaum_pedersen"

import {ElGamalCiphertext, ElGamalKeyPair, elgamal_add} from "./elgamal"
import {P, Q, G, ElementModP, ElementModQ, ZERO_MOD_Q, add_q,
  // ElementModQorInt
} from "./group"
import { hash_elems, CryptoHashCheckable } from "./hash";
import {ElectionObjectBase, OrderedObjectBase} from "./election_object_base";
import {Transform, Type} from "class-transformer";
import "reflect-metadata";
import { get_optional } from "./utils";
import { create_ballot_hash } from "./simple_elections";
// import { create_ballot_hash } from "./simple_elections";

//!!! Caution: This operation do sort in place! It mutates the compared arrays' order!
/**
 * We want to compare lists of election objects as if they're sets. We fake this by first
 * sorting them on their object ids, then using regular list comparison.
 * @param list1 list of election objects that need to be compared with
 * @param list2 list of election objects that need to be compared with
 */
export function _list_eq(list1: ElectionObjectBase[], list2: ElectionObjectBase[]): boolean{
  list1.sort((a, b) => (a.object_id < b.object_id) ? -1:1);
  list2.sort((a, b) => (a.object_id < b.object_id) ? -1:1);
  if (list1 === list2) return true;
  if (list1 == null || list2 == null) return false;
  if (list1.length !== list2.length) return false;
  for (let i = 0; i < list1.length; i++) {
    if (list1[i] !== list2[i]) {
      return false;
    }
  }
  return true;
}

export class ExtendedData {
    // """
    // ExtendedData represents any arbitrary data expressible as a string with a length.
    // This class is used primarily as a field on a selection to indicate a write-in candidate text value
    // """

    value: string
    length: number

    constructor(value: string, length: number) {
        this.value = value;
        this.length = length;
    }
}

export class PlaintextBallot implements ElectionObjectBase {
    // """
    // A PlaintextBallot represents a voters selections for a given ballot and ballot style
    // :field object_id: A unique Ballot ID that is relevant to the external system
    // """
    object_id: string;
    style_id: string;
    // The object id of this specific ballot. Will also appear in any corresponding encryption of this ballot.

    @Type(() => PlaintextBallotContest)
    contests: PlaintextBallotContest[];
    // The list of contests for this ballot
    public constructor(object_id: string, style_id: string, contests: PlaintextBallotContest[]){
        this.object_id = object_id;
        this.style_id = style_id;
        this.contests = contests;
    }

    public is_valid(expected_ballot_style_id: string): boolean {
        // """
        // Check if expected ballot style is valid
        // :param expected_ballot_style_id: Expected ballot style id
        // :return: True if valid
        // """
        if (this.style_id !== expected_ballot_style_id) {
            console.log(`invalid ballot_style: for: ${this.object_id} expected(${expected_ballot_style_id}) actual(${this.style_id})`);
            return false;
        }
        return true;
    }


    public equals(other: any): boolean {
        return (
            other instanceof PlaintextBallot
            && this.style_id === other.style_id
            && _list_eq(this.contests, other.contests)
        )
    }


    public notEquals(other: any): boolean {
        return !this.equals(other);
    }

}

export class PlaintextBallotContest implements OrderedObjectBase {
    // """
    // A PlaintextBallotContest represents the selections made by a voter for a specific ContestDescription
    // this class can be either a partial or a complete representation of a contest dataset.  Specifically,
    // a partial representation must include at a minimum the "affirmative" selections of a contest.
    // A complete representation of a ballot must include both affirmative and negative selections of
    // the contest, AND the placeholder selections necessary to satisfy the ConstantChaumPedersen proof
    // in the CiphertextBallotContest.
    // Typically partial contests are passed into Electionguard for memory constrained systems,
    // while complete contests are passed into ElectionGuard when running encryption on an existing dataset.
    // """

    sequence_order: number;

    object_id: string;

    @Type(() => PlaintextBallotSelection)
    ballot_selections: PlaintextBallotSelection[];
    // The voter's selections. 1 implies a vote for. 0 implies no vote.

    public constructor(object_id: string, sequence_order: number, selections: PlaintextBallotSelection[]){
        this.sequence_order = sequence_order;
        this.object_id = object_id;
        this.ballot_selections = selections;
    }

    public is_valid(
        expected_object_id: string,
        expected_number_selections: number,
        expected_number_elected: number,
        votes_allowed?: number
    ): boolean {
        // """
        // Given a PlaintextBallotContest returns true if the state is representative of the expected values.
        // Note: because this class supports partial representations, undervotes are considered a valid state.
        // """

        if (this.object_id !== expected_object_id) {
            console.log(`invalid object_id: expected(${expected_object_id}) actual(${this.object_id})`);
            return false;
        }


        if (this.ballot_selections.length > expected_number_selections) {
            console.log(`invalid number_selections: expected(${expected_number_selections}) actual(${this.ballot_selections.length})`)
            return false;
        }

        let number_elected = 0;
        let votes = 0;

        // Verify the selections are well-formed
        for (const selection of this.ballot_selections) {
            votes += selection.vote;
            if (selection.vote >= 1) {
                number_elected += 1;
            }
        }


        if (number_elected > expected_number_elected) {
            console.log(`invalid number_elected: expected(${expected_number_elected}) actual(${number_elected})`);
            return false;
        }

        if (votes_allowed !== undefined && votes > votes_allowed) {
            console.log(`invalid votes: expected(${votes_allowed}) actual(${votes})`);
            return false;
        }

        return true;
    }

    public equals(other: any): boolean {
        return other instanceof PlaintextBallotContest && this.object_id === other.object_id && _list_eq(
            this.ballot_selections, other.ballot_selections
        );
    }

    public notEquals(other: any): boolean {
        return !this.equals(other);
    }

    public num_selections(): number{
        return this.ballot_selections.length;
    }

    public is_overvoted(): boolean{
        let votes_cast = 0;
        for(const selection of this.ballot_selections){
            votes_cast += selection.vote;
        }
        return votes_cast > 1 ;
    }
}


export class PlaintextBallotSelection implements OrderedObjectBase {
    // """
    // A BallotSelection represents an individual selection on a ballot.
    // This class accepts a `vote` integer field which has no constraints
    // in the ElectionGuard Data Specification, but is constrained logically
    // in the application to resolve to `False` or `True` aka only 0 and 1 is
    // supported for now.
    // This class can also be designated as `is_placeholder_selection` which has no
    // context to the data specification but is useful for running validity checks internally
    // an `extended_data` field exists to support any arbitrary data to be associated
    // with the selection.  In practice, this field is the cleartext representation
    // of a write-in candidate value.  In the current implementation these values are
    // discarded when encrypting.
    // """

    // The object id of this specific ballot.
    // Will also appear in any corresponding plaintext of this ballot.
    object_id: string;

    sequence_order: number;


    //Hash of the election

    vote: number;

    is_placeholder_selection = false;
    // """Determines if this is a placeholder selection"""

    // # TODO: ISSUE #35: encrypt/decrypt
    @Type(() => ExtendedData)
    extended_data?: ExtendedData = undefined;
    // """
    // an optional field of arbitrary data, such as the value of a write-in candidate
    // """

    // 1 implies a vote for. 0 implies no vote.
    public constructor(object_id: string, sequence_order: number, vote: number, is_placeholder_selection: boolean, extened_data?: ExtendedData){
        this.object_id = object_id;
        this.sequence_order = sequence_order;
        this.vote = vote;
        this.is_placeholder_selection = is_placeholder_selection;
        this.extended_data = extened_data;
    }

    public is_valid(expected_object_id: string): boolean {
        // """
        // Given a PlaintextBallotSelection validates that the object matches an expected object
        // and that the plaintext string can resolve to a valid representation
        // """

        if (this.object_id !== expected_object_id) {
            console.log(`invalid object_id: expected(${expected_object_id}) actual(${this.object_id})`);
            return false;
        }

        const vote = this.vote;
        if (vote < 0 || vote > 1) {
            console.log(`Currently only supporting choices of 0 or 1: ${this.toString()}`);
            return false;
        }

        return true;
    }

    public equals(other: any): boolean {
        return (
            other instanceof PlaintextBallotSelection
            && this.object_id === other.object_id
            && this.vote === other.vote
            && this.is_placeholder_selection === other.is_placeholder_selection
            && this.extended_data === other.extended_data
        )
    }

    public notEquals(other: any): boolean {
        return !this.equals(other);
    }
}

export class CiphertextSelectionTally{
    name: string;
    // Candidate name, or `PLACEHOLDER` for a placeholder selection.

    total: ElGamalCiphertext;
    // Tally of encrypted selections.
    public constructor(name: string, total: ElGamalCiphertext){
        this.name = name;
        this.total = total;
    }
}


export class CiphertextBallot extends CryptoHashCheckable implements ElectionObjectBase{
    // The object id of this specific ballot.
    // Will also appear in any corresponding plaintext of this ballot.
    object_id: string;

    //The `object_id` of the `BallotStyle` in the `Election` Manifest
    style_id: string;

    //Hash of the election manifest
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    manifest_hash: ElementModQ;

    //Seed for ballot code
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    code_seed: ElementModQ;

    //List of contests for this ballot
    @Type(() => CiphertextBallotContest)
    contests: CiphertextBallotContest[];

    //Unique ballot code for this ballo
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    code: ElementModQ;

    //Timestamp at which the ballot encryption is generated in tick
    timestamp: number;

    //The hash of the encrypted ballot representation
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    crypto_hash: ElementModQ;

    //The nonce used to encrypt this ballot. Sensitive & should be treated as a secret
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    nonce: ElementModQ | undefined;

    public constructor(ballot_id: string,
                       style_id: string,
                       manifest_hash: ElementModQ,
                       code_seed: ElementModQ,
                       contests: CiphertextBallotContest[],
                       code: ElementModQ,
                       timestamp: number,
                       crypto_hash:ElementModQ,
                       nonce?: ElementModQ) {
        super();
        this.object_id = ballot_id;
        this.style_id = style_id;
        this.manifest_hash = manifest_hash;
        this.code_seed = code_seed;
        this.contests = contests;
        this.code = code;
        this.timestamp = timestamp;
        this.crypto_hash = crypto_hash;
        this.nonce = nonce;
    }

    //return: a representation of the election and the external Id in the nonce's used
    //       to derive other nonce values on the ballot
    public nonce_seed(
      manifest_hash: ElementModQ,
      object_id: string,
      nonce: ElementModQ): ElementModQ{

      return hash_elems([manifest_hash, object_id, nonce])
    }

    //return: a hash value derived from the description hash, the object id, and the nonce value
    //                 suitable for deriving other nonce values on the ballot
    public hashed_ballot_nonce(): ElementModQ | null | undefined{
        if (this.nonce == null) {
            return null;
        }
        return this.nonce_seed(this.manifest_hash, this.object_id, this.nonce);
    }

    //Given an encrypted Ballot, generates a hash, suitable for rolling up
    //         into a hash for an entire ballot / ballot code. Of note, this particular hash examines
    //         the `manifest_hash` and `ballot_selections`, but not the proof.
    //         This is deliberate, allowing for the possibility of ElectionGuard variants running on
    //         much more limited hardware, wherein the Disjunctive Chaum-Pedersen proofs might be computed
    //         later on.
    public crypto_hash_with(encryption_seed: ElementModQ):ElementModQ{
        if (this.contests == null) {
          return ZERO_MOD_Q;
        }
        const contest_hashes = []
        for ( let i = 0; i < this.contests.length; i ++) {
          contest_hashes.push(this.contests[i].crypto_hash);
        }
        return hash_elems([this.object_id, encryption_seed, ...contest_hashes]);
    }

    //Given an encrypted Ballot, validates the encryption state against a specific seed and public key
    //         by verifying the states of this ballot's children (BallotContest's and BallotSelection's).
    //         Calling this function expects that the object is in a well-formed encrypted state
    //         with the `contests` populated with valid encrypted ballot selections,
    //         and the ElementModQ `manifest_hash` also populated.
    //         Specifically, the seed in this context is the hash of the Election Manifest,
    //         or whatever `ElementModQ` was used to populate the `manifest_hash` field.
    //

    //done, but need supports in contest
    public  is_valid_encryption(
      encryption_seed: ElementModQ,
      elgamal_public_key: ElementModP,
      crypto_extended_base_hash: ElementModQ,
    ): boolean{
        if (encryption_seed != this.manifest_hash) {
            return false;
        }
        const recalculated_crypto_hash = this.crypto_hash_with(encryption_seed);
       if (this.crypto_hash != recalculated_crypto_hash) {
            return false;
       }

       //Check the proofs on the ballot
      const valid_proofs: boolean[] = [];
       for (const contest of this.contests) {
         for (const selection of contest.ballot_selections) {
           valid_proofs.push(
             selection.is_valid_encryption(
               selection.description_hash,
               elgamal_public_key,
               crypto_extended_base_hash
             )
           );
           valid_proofs.push(
             contest.is_valid_encryption(
               contest.description_hash,
               elgamal_public_key,
               crypto_extended_base_hash
             )
           );
         }
       }
      return valid_proofs.every((elem)=>elem);
    }



}

export class CiphertextBallotContest extends CryptoHashCheckable implements OrderedObjectBase{

  object_id: string;

  sequence_order: number;

  //Hash from contestDescription
  @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
  description_hash: ElementModQ;

  //Collection of ballot selections
  @Type(() => CiphertextBallotSelection)
  ballot_selections: CiphertextBallotSelection[];

  //The encrypted representation of all of the vote fields (the contest total)
  @Type(() => ElGamalCiphertext)
  ciphertext_accumulation: ElGamalCiphertext;

  //Hash of the encrypted values
  @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
  crypto_hash: ElementModQ;

  //The nonce used to generate the encryption. Sensitive & should be treated as a secret
  @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
  nonce?: ElementModQ = undefined;

  //The proof demonstrates the sum of the selections does not exceed the maximum
  //     available selections for the contest, and that the proof was generated with the nonce
  @Type(() => ConstantChaumPedersenProof)
  proof?: ConstantChaumPedersenProof = undefined;

    public constructor(
      object_id: string,
      sequence_order: number,
      description_hash: ElementModQ,
      ballot_selections: CiphertextBallotSelection[],
      ciphertext_accumulation: ElGamalCiphertext,
      crypto_hash: ElementModQ,
      nonce?: ElementModQ,
      proof?: ConstantChaumPedersenProof
      ){
        super();
        this.object_id = object_id;
        this.sequence_order = sequence_order;
        this.description_hash = description_hash;
        this.ballot_selections = ballot_selections;
        this.ciphertext_accumulation = ciphertext_accumulation;
        this.crypto_hash = crypto_hash;
        this.nonce = nonce;
        this.proof = proof;
    }

    public equals(other: any): boolean {
        return (
            other instanceof CiphertextBallotContest
            && this.object_id === other.object_id
            && _list_eq(this.ballot_selections, other.ballot_selections)
            && this.description_hash === other.description_hash
            && this.crypto_hash === other.crypto_hash
            && this.nonce === other.nonce
            && this.proof === other.proof
        );
    }

    public notEquals(other: any): boolean {
        return !this.equals(other);
    }


    public aggregate_nonce(): ElementModQ | undefined {
        // """
        // :return: an aggregate nonce for the contest composed of the nonces of the selections
        // """
        return _ciphertext_ballot_contest_aggregate_nonce(
            this.object_id, this.ballot_selections
        )
    }

    public elgamal_accumulate(): ElGamalCiphertext {
        // """
        // Add the individual ballot_selections `message` fields together, suitable for use
        // in a Chaum-Pedersen proof.
        // """
        return _ciphertext_ballot_elgamal_accumulate(this.ballot_selections);
    }


    public is_valid_encryption(
        encryption_seed: ElementModQ,
        elgamal_public_key: ElementModP,
        crypto_extended_base_hash: ElementModQ,
    ): boolean {
        // """
        // Given an encrypted BallotContest, validates the encryption state against a specific seed and public key
        // by verifying the accumulated sum of selections match the proof.
        // Calling this function expects that the object is in a well-formed encrypted state
        // with the `ballot_selections` populated with valid encrypted ballot selections,
        // the ElementModQ `description_hash`, the ElementModQ `crypto_hash`,
        // and the ConstantChaumPedersenProof all populated.
        // Specifically, the seed in this context is the hash of the ContestDescription,
        // or whatever `ElementModQ` was used to populate the `description_hash` field.
        // """
        if (encryption_seed !== this.description_hash) {
            console.log(`mismatching contest hash: ${this.object_id} expected(${encryption_seed.toString()}), actual(${this.description_hash.toString()})`);
            return false;
        }


        const recalculated_crypto_hash = this.crypto_hash_with(encryption_seed);
        if (this.crypto_hash !== recalculated_crypto_hash) {
            console.log(`mismatching crypto hash: ${this.object_id} expected(${recalculated_crypto_hash.toString()}), actual(${this.crypto_hash})`);
            return false;
        }


        // NOTE: this check does not verify the proofs of the individual selections by design.

        if (this.proof === undefined) {
            console.log(`no proof exists for: ${this.object_id}`);
            return false;
        }


        const computed_ciphertext_accumulation = this.elgamal_accumulate();
        // Verify that the contest ciphertext matches the elgamal accumulation of all selections
        if (this.ciphertext_accumulation !== computed_ciphertext_accumulation) {
            console.log(`ciphertext does not equal elgamal accumulation for : ${this.object_id}`);
            return false;
        }


        // # Verify the sum of the selections matches the proof
        return this.proof.is_valid(
            computed_ciphertext_accumulation,
            elgamal_public_key,
            crypto_extended_base_hash,
        )
    }



    // public num_selections(): number{
    //     return this.selections.length;
    // }
    //
    public crypto_hash_with(encryption_seed: ElementModQ): ElementModQ {
        return _ciphertext_ballot_context_crypto_hash(this.object_id,
          this.ballot_selections,
          encryption_seed);
    }

}

//A CiphertextBallotSelection represents an individual encrypted selection on a ballot.
//     This class accepts a `description_hash` and a `ciphertext` as required parameters
//     in its constructor.
//     When a selection is encrypted, the `description_hash` and `ciphertext` required fields must
//     be populated at construction however the `nonce` is also usually provided by convention.
//     After construction, the `crypto_hash` field is populated automatically in the `__post_init__` cycle
//     A consumer of this object has the option to discard the `nonce` and/or discard the `proof`,
//     or keep both values.
//     By discarding the `nonce`, the encrypted representation and `proof`
//     can only be regenerated if the nonce was derived from the ballot's master nonce.  If the nonce
//     used for this selection is truly random, and it is discarded, then the proofs cannot be regenerated.
//     By keeping the `nonce`, or deriving the selection nonce from the ballot nonce, an external system can
//     regenerate the proofs on demand.  This is useful for storage or memory constrained systems.
//     By keeping the `proof` the nonce is not required fotor verify the encrypted selection.
//
export class CiphertextBallotSelection extends CryptoHashCheckable implements OrderedObjectBase{

  object_id: string;

  @Transform(({value}) => parseInt(value, 16))
  sequence_order: number;

  //The SelectionDescription hash
  @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
  description_hash: ElementModQ;

  //The encrypted representation of the vote field
  @Type(() => ElGamalCiphertext)
  ciphertext: ElGamalCiphertext;

  //The hash of the encrypted values
  @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
  crypto_hash: ElementModQ;

  //Determines if this is a placeholder selection
  is_placeholder_selection = false;

  //The nonce used to generate the encryption. Sensitive & should be treated as a secret
  @Transform(({value}) => value == null ? value : new ElementModQ(BigInt("0x"+value)))
  nonce?: ElementModQ = undefined;

  //The proof that demonstrates the selection is an encryption of 0 or 1, and was encrypted using the `nonce`
  @Type(() => DisjunctiveChaumPedersenProof)
  proof?: DisjunctiveChaumPedersenProof = undefined;

  //encrypted representation of the extended_data field
  @Type(() => ElGamalCiphertext)
  extended_data?: ElGamalCiphertext = undefined;

    public constructor(
      object_id: string,
      sequence_order: number,
      description_hash: ElementModQ,
      ciphertext: ElGamalCiphertext,
      crypto_hash: ElementModQ,
      is_placeholder_selection: boolean,
      nonce?: ElementModQ,
      proof?: DisjunctiveChaumPedersenProof,
      extended_data?: ElGamalCiphertext,
                       ){
        super();
        this.object_id = object_id;
        this.sequence_order = sequence_order;
        this.description_hash = description_hash;
        this.ciphertext = ciphertext;
        this.crypto_hash = crypto_hash;
        this.is_placeholder_selection = is_placeholder_selection;
        this.nonce = nonce;
        this.proof = proof;
        this.extended_data = extended_data;
    }

    public is_valid_encryption(
        encryption_seed: ElementModQ,
        elgamal_public_key: ElementModP,
        crypto_extended_base_hash: ElementModQ,
    ): boolean {
        // """
        // Given an encrypted BallotSelection, validates the encryption state against a specific seed and public key.
        // Calling this function expects that the object is in a well-formed encrypted state
        // with the elgamal encrypted `message` field populated along with
        // the DisjunctiveChaumPedersenProof`proof` populated.
        // the ElementModQ `description_hash` and the ElementModQ `crypto_hash` are also checked.

        // :param encryption_seed: the hash of the SelectionDescription, or
        //                   whatever `ElementModQ` was used to populate the `description_hash` field.
        // :param elgamal_public_key: The election public key
        // """

        if (encryption_seed !== this.description_hash) {
            console.log(`mismatching selection hash: ${this.object_id} expected(${encryption_seed.toString()}), actual(${this.description_hash.toString()})`);
            return false;
        }


        const recalculated_crypto_hash = this.crypto_hash_with(encryption_seed);
        if (this.crypto_hash !== recalculated_crypto_hash) {
            console.log(`mismatching crypto hash: ${this.object_id} expected(${recalculated_crypto_hash.toString()}), actual(${this.crypto_hash.toString()})`);
            return false;
        }


        if (this.proof === null) {
            console.log(`no proof exists for: ${this.object_id}`);
            return false;
        }


        return get_optional(this.proof).is_valid(
            this.ciphertext, elgamal_public_key, crypto_extended_base_hash
        );
    }


    public crypto_hash_with(encryption_seed: ElementModQ): ElementModQ {
        return _ciphertext_ballot_selection_crypto_hash_with(this.object_id, encryption_seed, this.ciphertext)
    }
}

export class PlaintextBallotSelectionWithProof {
    selection: PlaintextBallotSelection;
    // The decrypted version of a ciphertext

    decryption_proof: ChaumPedersenDecryptionProof;
    // Proof that the decrypted version is consistent with the ciphertext

    public constructor(selection: PlaintextBallotSelection, decryption_proof: ChaumPedersenDecryptionProof){
        this.selection = selection;
        this.decryption_proof = decryption_proof;
    }
}

export class PlaintextContestWithProofs {

    selections: PlaintextBallotSelectionWithProof[];
    // Each selection along with its proof

    public constructor(selections: PlaintextBallotSelectionWithProof[]){
        this.selections = selections;
    }

    public num_selections(): number {
        return this.selections.length;
    }
}

export class PlaintextBallotWithProofs {
    ballot_id: string;
    // The object id of this specific ballot. Will also appear in any corresponding plaintext of this ballot.

    contests: PlaintextContestWithProofs[];
    // Each selection along with its proof

    public constructor(ballot_id: string, contests: PlaintextContestWithProofs[]){
        this.ballot_id = ballot_id;
        this.contests = contests;
    }

    public  num_contests(): number {
        return this.contests.length;
    }
}


export class PublicElectionContext {
    // Election context that would be available to any observer of the election.

    election_name: string;
    // Unique string defining the name of the election.

    names: string[];
    // Candidate names for a simple, 1-of-n election.

    public_key: ElementModP;
    // Public encryption key for the election.

    base_hash: ElementModQ;
    // A constant used throughout the election.

    public constructor(election_name: string, names: string[], public_key: ElementModP, base_hash: ElementModQ){
        this.election_name = election_name;
        this.names = names;
        this.public_key = public_key;
        this.base_hash = base_hash;
    }

    public to_public_election_context(): PublicElectionContext {
        return this;
    }

    public get_public_key(): ElementModP{
        return this.public_key;
    }
}

export class PrivateElectionContext {
    // Election context that would only be available to an election administrator.

    election_name: string;
    // Unique string defining the name of the election.

    names: string[];
    // Candidate names for a simple, 1-of-n election.

    keypair: ElGamalKeyPair;
    // Public and private keys used for the election.

    base_hash: ElementModQ;
    // A constant used throughout the election.

    public constructor(election_name: string, names: string[], keypair: ElGamalKeyPair, base_hash: ElementModQ){
        this.election_name = election_name;
        this.names = names;
        this.keypair = keypair;
        this.base_hash = base_hash;
    }

    public to_public_election_context(): PublicElectionContext{
        return new PublicElectionContext(
            this.election_name,
            this.names,
            this.keypair.public_key,
            this.base_hash
        )
    }

    public get_public_key(): ElementModP{
        return this.keypair.public_key
    }


}

export class CiphertextElectionContext  {
    //    """`CiphertextElectionContext` is the ElectionGuard representation of a specific election.
    number_of_guardians: number;
    //    The number of guardians necessary to generate the public key

    quorum:number;
    // The quorum of guardians necessary to decrypt an election.  Must be less than `number_of_guardians`

    elgamal_public_key:ElementModP;
    // the `joint public key (K)` in the specification

    commitment_hash: ElementModQ;
    // the `commitment hash H(K 1,0 , K 2,0 ... , K n,0 )` of the public commitments
    // guardians make to each other in the specification

    manifest_hash: ElementModQ;
    // The hash of the election metadata

    crypto_base_hash: ElementModQ;
    // The `base hash code (𝑄)` in the specification

    crypto_extended_base_hash: ElementModQ;
    // The `extended base hash code (𝑄')` in specification

    extended_data?: Map<string, string>;
    // Data to allow extending the context for special cases.

    public constructor(
        number_of_guardians: number,
        quorum: number,
        elgamal_public_key:ElementModP,
        commitment_hash: ElementModQ,
        manifest_hash: ElementModQ,
        crypto_base_hash: ElementModQ,
        crypto_extended_base_hash: ElementModQ,
        extended_data?: Map<string, string>
    ){
        this.number_of_guardians = number_of_guardians;
        this.quorum = quorum;
        this.elgamal_public_key = elgamal_public_key;
        this.commitment_hash = commitment_hash;
        this.manifest_hash = manifest_hash;
        this.crypto_base_hash = crypto_base_hash;
        this.crypto_extended_base_hash = crypto_extended_base_hash;
        this.extended_data = extended_data;
    }
}

export function make_ciphertext_election_context(
        number_of_guardians: number,
        quorum: number,
        elgamal_public_key:ElementModP,
        commitment_hash: ElementModQ,
        manifest_hash: ElementModQ,
        extended_data?: Map<string, string>
): CiphertextElectionContext{

    const crypto_base_hash = hash_elems(
        [new ElementModP(P), new ElementModQ(Q), new ElementModP(G) ,number_of_guardians, quorum,
        manifest_hash]);
    const crypto_extended_base_hash = hash_elems([crypto_base_hash, commitment_hash]);
    return new CiphertextElectionContext(
        number_of_guardians,
        quorum,
        elgamal_public_key,
        commitment_hash,
        manifest_hash,
        crypto_base_hash,
        crypto_extended_base_hash,
        extended_data);
}

// Notes for Arthur: I deleted all object-id for now for simplicity. Let me know if it is required and I can add it later.
export function _ciphertext_ballot_context_crypto_hash(
    object_id:string,
    ballot_selections: CiphertextBallotSelection[],
    encryption_seed: ElementModQ):ElementModQ{
    if (ballot_selections.length == 0){
        console.log(
            `mismatching ballot_selections state: ${object_id} expected(some), actual(none)`);
        return ZERO_MOD_Q;
    }
    const total_with_selection_hashes = [object_id, encryption_seed]
    for ( let i = 0; i < ballot_selections.length; i ++) {
        total_with_selection_hashes.push(ballot_selections[i].crypto_hash);
    }
    return hash_elems(total_with_selection_hashes)
}
export function _ciphertext_ballot_selection_crypto_hash_with(
  object_id: string,
  encryption_seed: ElementModQ,
  ciphertext: ElGamalCiphertext): ElementModQ{
    return hash_elems([object_id, encryption_seed, ciphertext.crypto_hash()]);
}


export function _ciphertext_ballot_elgamal_accumulate(
    ballot_selections: CiphertextBallotSelection[],
): ElGamalCiphertext {
    const ciphertexts: ElGamalCiphertext[] = [];
    for (const selection of ballot_selections) {
        ciphertexts.push(selection.ciphertext);
    }
    return elgamal_add(...ciphertexts);
}


export function _ciphertext_ballot_contest_aggregate_nonce(
    object_id: string, ballot_selections: CiphertextBallotSelection[]
) : ElementModQ | undefined {
    const selection_nonces: ElementModQ[] = [];
    for (let i = 0; i < ballot_selections.length; i++) {
        const selection = ballot_selections[i];
        if (selection.nonce === undefined) {
            console.log(`missing nonce values for contest ${object_id} cannot calculate aggregat nonce`);
            return undefined;
        }

        selection_nonces.push(selection.nonce);
    }


    return add_q(...selection_nonces);
}


export function make_ciphertext_ballot_selection(
    object_id: string,
    sequence_order: number,
    description_hash: ElementModQ,
    ciphertext: ElGamalCiphertext,
    elgamal_public_key: ElementModP,
    crypto_extended_base_hash: ElementModQ,
    proof_seed: ElementModQ,
    selection_representation: number,
    is_placeholder_selection = false,
    nonce?: ElementModQ,
    crypto_hash?: ElementModQ,
    proof?: DisjunctiveChaumPedersenProof,
    extended_data?: ElGamalCiphertext):CiphertextBallotSelection{

    if (crypto_hash == null) {
        crypto_hash = _ciphertext_ballot_selection_crypto_hash_with(object_id, description_hash, ciphertext);
    }
    // console.log(crypto_hash)
    if (proof == null) {
        proof = make_disjunctive_chaum_pedersen(ciphertext, get_optional(nonce), elgamal_public_key, crypto_extended_base_hash, proof_seed, selection_representation);
    }


    return new CiphertextBallotSelection(
        object_id,
        sequence_order,
        description_hash,
        ciphertext,
        get_optional(crypto_hash),
        is_placeholder_selection,
        nonce,
        proof,
        extended_data
    )
}

export function make_ciphertext_ballot_contest(
    object_id: string,
    sequence_order: number,
    description_hash: ElementModQ,
    ballot_selections: CiphertextBallotSelection[],
    elgamal_public_key: ElementModP,
    crypto_extended_base_hash: ElementModQ,
    proof_seed: ElementModQ,
    number_elected: number,
    nonce?: ElementModQ,
    crypto_hash?: ElementModQ,
    proof?: ConstantChaumPedersenProof,
): CiphertextBallotContest {
    // """
    // Constructs a `CipherTextBallotContest` object. Most of the parameters here match up to fields
    // in the class, but this helper function will optionally compute a Chaum-Pedersen proof if the
    // ballot selections include their encryption nonces. Likewise, if a crypto_hash is not provided,
    // it will be derived from the other fields.
    // """
    if (crypto_hash === undefined) {
        crypto_hash = _ciphertext_ballot_context_crypto_hash(
            object_id, ballot_selections, description_hash
        )
    }


    const aggregate = _ciphertext_ballot_contest_aggregate_nonce(object_id, ballot_selections);
    const elgamal_accumulation = _ciphertext_ballot_elgamal_accumulate(ballot_selections);
    if (proof === undefined) {
        proof = make_constant_chaum_pedersen(
            elgamal_accumulation,
            BigInt(number_elected),
            get_optional(aggregate),
            elgamal_public_key,
            proof_seed,
            crypto_extended_base_hash,
        );
    }

    return new CiphertextBallotContest(
        object_id,
        sequence_order,
        description_hash,
        ballot_selections,
        elgamal_accumulation,
        crypto_hash,
        nonce,
        proof,
    );
}

export function make_ciphertext_ballot(
    object_id: string,
    style_id: string,
    manifest_hash: ElementModQ,
    contests: CiphertextBallotContest[],
    code_seed?: ElementModQ,
    nonce?: ElementModQ,
    timestamp?: number,
    ballot_code?: ElementModQ,
): CiphertextBallot {
    // """
    // Makes a `CiphertextBallot`, initially in the state where it's neither been cast nor spoiled.
    // :param object_id: the object_id of this specific ballot
    // :param style_id: The `object_id` of the `BallotStyle` in the `Election` Manifest
    // :param manifest_hash: Hash of the election manifest
    // :param crypto_base_hash: Hash of the cryptographic election context
    // :param contests: List of contests for this ballot
    // :param timestamp: Timestamp at which the ballot encryption is generated in tick
    // :param code_seed: Seed for ballot code
    // :param nonce: optional nonce used as part of the encryption process
    // """

    if (contests.length === 0) {
        console.log("ciphertext ballot with no contests");
    }

    const contest_hash = create_ballot_hash(object_id, manifest_hash, contests);
    // timestamp = timestamp === undefined ? to_ticks(new Date()) : timestamp;
    timestamp = 1635015400;
    if (code_seed === undefined) {
        code_seed = manifest_hash;
    }

    if (ballot_code === undefined) {
        ballot_code = get_ballot_code(code_seed, timestamp, contest_hash);
    }


    return new CiphertextBallot(
        object_id,
        style_id,
        manifest_hash,
        code_seed,
        contests,
        ballot_code,
        timestamp,
        contest_hash,
        nonce,
    )

}

export function get_ballot_code(
    prev_code: ElementModQ, timestamp: number, ballot_hash: ElementModQ
): ElementModQ {
    // """
    // Get the rotated code for a particular ballot.
    // :param prev_code: Previous code or starting hash from device
    // :param timestamp: Timestamp in ticks
    // :param ballot_hash: Hash of ballot
    // :return: code
    // """
    return hash_elems([prev_code, timestamp, ballot_hash]);
}

export function to_ticks(date_time: Date): number {
    // """
    // Return the number of ticks for a date time.
    // Ticks are defined here as number of seconds since the unix epoch (00:00:00 UTC on 1 January 1970)
    // :param date_time: Date time to convert
    // :return: number of ticks
    // """

    // JavaScript uses milliseconds as the unit of measurement and getTime() should always return UTC time
    // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/getTime
    const ticks = date_time.getTime() / 1000
    return Math.floor(ticks);
}




export type AnyElectionContext = PublicElectionContext | PrivateElectionContext;





