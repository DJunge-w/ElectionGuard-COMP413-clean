import {
    CiphertextBallot,
    PlaintextBallot,
    PlaintextBallotSelection,
    CiphertextBallotSelection,
    // PrivateElectionContext,
    // CiphertextSelectionTally,
    AnyElectionContext,
    PlaintextBallotSelectionWithProof,
    // PlaintextContestWithProofs,
    // PlaintextBallotWithProofs,
    CiphertextBallotContest,
    // _ciphertext_ballot_context_crypto_hash,
    PlaintextBallotContest,
    CiphertextElectionContext,
    make_ciphertext_ballot_selection,
    make_ciphertext_ballot_contest,
    make_ciphertext_ballot
} from "./simple_election_data"
// import { ElGamalCiphertext } from "./elgamal"
import { ElementModQ,
    // TWO_MOD_Q,
    ElementModP,
    // rand_q,
    // add_q,
    // R
} from "./group"
// import {Nonces} from "./nonces"
// import * as el from "./elgamal"
// import * as cp from "./chaum_pedersen"
import {get_optional} from "./utils";
import {
    hash_elems } from "./hash"
import { ContestDescription, ContestDescriptionWithPlaceholders, InternalManifest, SelectionDescription } from "./manifest"
// import {
//   // from_file_to_class,
//   // from_file_to_PlaintextBallot,
//   // object_log
// } from "./serialization";
import {sequence_order_sort} from "./election_object_base";
import { Nonces } from "./nonces";
import { elgamal_encrypt } from "./elgamal";

// const PLACEHOLDER_NAME = "PLACEHOLDER"

export function selection_from(
                    description: SelectionDescription,
                    is_placeholder = false,
                    is_affirmative = false,
                ) : PlaintextBallotSelection {
        return new PlaintextBallotSelection(
            description.object_id,
            description.sequence_order,
            is_affirmative ? 1 : 0,
            is_placeholder
        );
    }

export function contest_from(description: ContestDescription) : PlaintextBallotContest {
    const selections:PlaintextBallotSelection[] = [];
    for (const selection_description of description.ballot_selections) {
        selections.push(selection_from(selection_description))
    }
    return new PlaintextBallotContest(description.object_id, description.sequence_order, selections);
}


export function encrypt_selection(selection: PlaintextBallotSelection,
                                  selection_description: SelectionDescription ,
                                    elgamal_public_key: ElementModP,
                                    crypto_extended_base_hash: ElementModQ,
                                    nonce_seed: ElementModQ,
                                    is_placeholder = false,
                                    should_verify_proofs = true
                                  ):
    (CiphertextBallotSelection | null) {
  should_verify_proofs;
//     //Given a selection and the necessary election context, encrypts the selection and returns the
//     //     encrypted selection plus the encryption nonce. If anything goes wrong, `None` is returned.
//     const public_key = context.elgamal_public_key;
//     const encryption = el.elgamal_encrypt(BigInt(selection.choice), seed_nonce, public_key);
//     if (!(encryption instanceof el.ElGamalCiphertext)){
//         return null;
//     }
//     const zero_or_one_pad = cp.make_disjunctive_chaum_pedersen(
//         encryption,
//         seed_nonce,
//         public_key,
//         context.crypto_extended_base_hash,
//         seed_nonce,
//         selection.choice
//     )

    // const cipher = make_ciphertext_ballot_selection(selection.name, seed_nonce, encryption, null, zero_or_one_pad);
    const  selection_description_hash = selection_description.crypto_hash()
    // console.log("inside encrypt selection");
    // console.log(selection.object_id);
    // console.log("before nonce:", selection_description_hash, nonce_seed)
    const nonce_sequence = new Nonces(selection_description_hash, nonce_seed);
    const selection_nonce = nonce_sequence.get(selection_description.sequence_order);
    const selection_representation = selection.vote;
    const disjunctive_chaum_pedersen_nonce = nonce_sequence.next();

    const elgamal_encryption = elgamal_encrypt(
            BigInt(selection_representation), selection_nonce, elgamal_public_key
        )
    // console.log("descrption hash", selection_description_hash)
    // console.log("crypto hash hash", selection_description.crypto_hash())


    const encrypted_selection = make_ciphertext_ballot_selection(
        selection.object_id,
        selection.sequence_order,
        selection_description_hash,
        get_optional(elgamal_encryption),
        elgamal_public_key,
        crypto_extended_base_hash,
        disjunctive_chaum_pedersen_nonce,
        selection_representation,
        is_placeholder,
        selection_nonce,
    );
    return encrypted_selection
}


export function encrypt_contest(contest: PlaintextBallotContest,
                                contest_description: ContestDescriptionWithPlaceholders,
                                elgamal_public_key: ElementModP,
                                crypto_extended_base_hash: ElementModQ,
                                nonce_seed: ElementModQ,
                                should_verify_proofs = true,

                            ): CiphertextBallotContest | null {
        should_verify_proofs;
        const contest_description_hash = contest_description.crypto_hash();
        const nonce_sequence = new Nonces(contest_description_hash, nonce_seed);
        const contest_nonce = nonce_sequence.get(contest_description.sequence_order);
        const chaum_pedersen_nonce = nonce_sequence.next();

        const encrypted_selections: CiphertextBallotSelection[] = [];
        let encrypted_selection = null;
        let selection_count  = 0;

        for (const description of contest_description.ballot_selections) {
            let has_selection = false
            for (const selection of contest.ballot_selections) {
                if (selection.object_id == description.object_id) {
                    has_selection = true
                    selection_count += selection.vote;
                    encrypted_selection = encrypt_selection(
                        selection,
                        description,
                        elgamal_public_key,
                        crypto_extended_base_hash,
                        contest_nonce,
                    );
                    break;
                }
            }
            if (has_selection == false) {
                encrypted_selection = encrypt_selection(
                    selection_from(description),
                    description,
                    elgamal_public_key,
                    crypto_extended_base_hash,
                    contest_nonce,
                );
            }
            encrypted_selections.push(get_optional(encrypted_selection))
        }

        for (const placeholder of contest_description.placeholder_selections) {
            let select_placeholder = false;
            if (selection_count < contest_description.number_elected) {
                selection_count += 1;
                select_placeholder = true;
            }
            encrypted_selection = encrypt_selection(selection_from(placeholder, true, select_placeholder), placeholder, elgamal_public_key, crypto_extended_base_hash, contest_nonce, true, true)
            encrypted_selections.push(get_optional(encrypted_selection))
        }
        const encrypted_contest = make_ciphertext_ballot_contest(
            contest.object_id,
            contest.sequence_order,
            contest_description_hash,
            encrypted_selections,
            elgamal_public_key,
            crypto_extended_base_hash,
            chaum_pedersen_nonce,
            contest_description.number_elected,
            contest_nonce,
        )
        return  encrypted_contest
    }

export function encrypt_ballot_contests(ballot:PlaintextBallot,
                                        description: InternalManifest,
                                        context: CiphertextElectionContext,
                                        nonce_seed:ElementModQ
                                        ): CiphertextBallotContest[]|null {

    const encrypted_contests: CiphertextBallotContest[] = [];

    console.log("ballot style id in simple elections ", ballot.style_id)
    for (const ballot_style_contest of description.get_contests_for(ballot.style_id)) {
        let use_contest = null;
        for (const contest of ballot.contests) {
            if (contest.object_id == ballot_style_contest.object_id) {
                use_contest = contest
                break
            }
        }
        if (use_contest == null) {
            use_contest = contest_from(ballot_style_contest);
        }
        const encrypted_contest = get_optional(encrypt_contest(
            use_contest,
            ballot_style_contest,
            context.elgamal_public_key,
            context.crypto_extended_base_hash,
            nonce_seed,
            ));
        encrypted_contests.push(encrypted_contest);
    }
    // console.log("encrypted contests is ", object_log(encrypted_contests));
    return encrypted_contests;
}


//change parameter to accept null only for testing and demo purpose!!!
export function encrypt_ballot(ballot: PlaintextBallot,
                               internal_manifest: InternalManifest,
                               context: CiphertextElectionContext,
                               encryption_seed: ElementModQ ,
                               nonce: ElementModQ,
                               should_verify_proofs  = true):
    (CiphertextBallot | null | undefined) {
    should_verify_proofs;

    // const inputs = from_file_to_class();
    const nonce_seed = hash_elems([internal_manifest.manifest_hash, ballot.object_id, nonce]);
    // pass & todo: change to internal_manifest.manifest_hash

    const encrypted_contests = get_optional(encrypt_ballot_contests(
        ballot, internal_manifest, context, nonce_seed
    ))

    const encrypted_ballot = make_ciphertext_ballot(ballot.object_id,
        ballot.style_id,
        internal_manifest.manifest_hash,
        encrypted_contests,
        encryption_seed,
        nonce,)

    if (encrypted_contests == null) {
        return null
    }

    return encrypted_ballot;
}

//Create the hash of the ballot contests.
export function create_ballot_hash(ballot_id: string,
                                   description_hash: ElementModQ,
                                   contests: CiphertextBallotContest[]): ElementModQ {
  const contests_hash = sequence_order_sort(contests).map(contest => contest.crypto_hash);
  return hash_elems([ballot_id, description_hash, ...contests_hash]);
}

export function validate_decrypted_selection(
    context: AnyElectionContext,
    plaintext: PlaintextBallotSelectionWithProof,
    ciphertext: CiphertextBallotSelection): boolean {
    //Validates that the plaintext is provably generated from the ciphertext. Returns true if everything is good.
    const plaintext_msg = plaintext.selection.vote;
    const public_key = context.get_public_key();
    const base_hash = context.base_hash;
    const is_valid = plaintext.decryption_proof.is_valid(BigInt(plaintext_msg), ciphertext.ciphertext, public_key, base_hash);
    return is_valid
}
