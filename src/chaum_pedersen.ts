// import { assert } from "console";
import { ElGamalCiphertext } from "./elgamal"

// import optional
// import dataclass from dataclasses

import { ElementModQ,
    ElementModP,
    g_pow_p,
    mult_p,
    pow_p,
    a_minus_b_q,
    a_plus_bc_q,
    add_q,
    negate_q,
    int_to_q,
    ZERO_MOD_Q,
    mult_inv_p,
    G,
    int_to_p_unchecked,
    int_to_p } from "./group"

import { hash_elems } from "./hash"
// import loggings

import { Nonces } from "./nonces"
import {Transform} from "class-transformer";

//Usage case for proof
export enum ProofUsage {
  Unknown = "Unknown",
  SecretValue = "Prove knowledge of secret value",
  SelectionLimit = "Prove value within selection's limit",
  SelectionValue = "Prove selection's value (0 or 1)",
}

export class DisjunctiveChaumPedersenProof {
    // Representation of disjunctive Chaum Pederson proof
    @Transform(({value}) => new ElementModP(BigInt("0x"+value)))
    proof_zero_pad: ElementModP;
    // a0 in the spec
    @Transform(({value}) => new ElementModP(BigInt("0x"+value)))
    proof_zero_data: ElementModP;
    // b0 in the spec
    @Transform(({value}) => new ElementModP(BigInt("0x"+value)))
    proof_one_pad: ElementModP;
    // a1 in the spec
    @Transform(({value}) => new ElementModP(BigInt("0x"+value)))
    proof_one_data: ElementModP;
    // b1 in the spec
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    proof_zero_challenge: ElementModQ;
    // c0 in the spec
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    proof_one_challenge: ElementModQ;
    // c1 in the spec
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    challenge: ElementModQ;
    // c in the spec
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    proof_zero_response: ElementModQ;
    // proof_zero_response in the spec
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    proof_one_response: ElementModQ;
    // proof_one_response in the spec
    @Transform(({value}) => value as ProofUsage)
    usage: ProofUsage = ProofUsage.SelectionValue;

    public constructor(a0: ElementModP,
                       b0: ElementModP,
                       a1: ElementModP,
                       b1: ElementModP,
                       c0: ElementModQ,
                       c1: ElementModQ,
                       c: ElementModQ,
                       v0: ElementModQ,
                       v1: ElementModQ,
                       usage: ProofUsage = ProofUsage.SelectionValue) {
        this.proof_zero_pad = a0;
        this.proof_zero_data = b0;
        this.proof_one_pad = a1;
        this.proof_one_data = b1;
        this.proof_zero_challenge = c0;
        this.proof_one_challenge = c1;
        this.challenge = c;
        this.proof_zero_response = v0;
        this.proof_one_response = v1;
        this.usage = usage;
    }

    public is_valid(message: ElGamalCiphertext, k: ElementModP, q: ElementModQ): boolean {
        const [alpha, beta] = [message.pad, message.data];
        const a0:ElementModP = this.proof_zero_pad;
        const b0:ElementModP = this.proof_zero_data;
        const a1:ElementModP = this.proof_one_pad;
        const b1:ElementModP = this.proof_one_data;
        const c0:ElementModQ = this.proof_zero_challenge;
        const c1:ElementModQ = this.proof_one_challenge;
        const c:ElementModQ = this.challenge;
        const v0:ElementModQ = this.proof_zero_response;
        const v1:ElementModQ = this.proof_one_response;
        const in_bounds_alpha:boolean = alpha.is_valid_residue();
        const in_bounds_beta:boolean = beta.is_valid_residue();
        const in_bounds_a0:boolean = a0.is_valid_residue();
        const in_bounds_b0:boolean = b0.is_valid_residue();
        const in_bounds_a1:boolean = a1.is_valid_residue();
        const in_bounds_b1:boolean = b1.is_valid_residue();
        const in_bounds_c0:boolean = c0.is_in_bounds();
        const in_bounds_c1:boolean = c1.is_in_bounds();
        const in_bounds_v0:boolean = v0.is_in_bounds();
        const in_bounds_v1:boolean = v1.is_in_bounds();
        const consistent_c:boolean = (add_q(c0, c1).equals(c)) && (add_q(c0, c1).equals(hash_elems([q, alpha, beta, a0, b0, a1, b1])));
        const consistent_gv0:boolean = g_pow_p(v0).equals(mult_p(a0, pow_p(alpha, c0)));
        const consistent_gv1:boolean = g_pow_p(v1).equals(mult_p(a1, pow_p(alpha, c1)));
        const consistent_kv0:boolean = pow_p(k, v0).equals(mult_p(b0, pow_p(beta, c0)));
        const consistent_gc1kv1:boolean = mult_p(g_pow_p(c1), pow_p(k, v1)).equals(mult_p(
            b1, pow_p(beta, c1)
        ));
        const success = (
            in_bounds_alpha
            && in_bounds_beta
            && in_bounds_a0
            && in_bounds_b0
            && in_bounds_a1
            && in_bounds_b1
            && in_bounds_c0
            && in_bounds_c1
            && in_bounds_v0
            && in_bounds_v1
            && consistent_c
            && consistent_gv0
            && consistent_gv1
            && consistent_kv0
            && consistent_gc1kv1
        );

        if (!success) {
            console.log("in_bounds_alpha: ", in_bounds_alpha, "in_bounds_beta: ", in_bounds_beta, "in_bounds_a0: ", in_bounds_a0,
            "in_bounds_b0: ", in_bounds_b0, "in_bounds_a1: ", in_bounds_a1, "in_bounds_b1: ", in_bounds_b1, "in_bounds_c0: ", in_bounds_c0,
            "in_bounds_c1: ", in_bounds_c1, "in_bounds_v0: ", in_bounds_v0, "in_bounds_v1: ", in_bounds_v1, "consistent_c: ", consistent_c,
            "consistent_gv0: ", consistent_gv0, "consistent_gv1: ", consistent_gv1, "consistent_kv0: ", consistent_kv0, "consistent_gc1kv1: ", consistent_gc1kv1,
            "k: ", k);
        }
        return success;

    }

}

// Representation of constant Chaum Pederson proof.
export class ConstantChaumPedersenProof {
    // a in the spec
    @Transform(({value}) => new ElementModP(BigInt("0x"+value)))
    pad: ElementModP;

    // b in the spec
    @Transform(({value}) => new ElementModP(BigInt("0x"+value)))
    data: ElementModP;

    // c in the spec
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    challenge: ElementModQ;

    // v in the spec
    @Transform(({value}) => new ElementModQ(BigInt("0x"+value)))
    response: ElementModQ;

    // constant value
    @Transform(({value}) => BigInt("0x" + value))
    constant: bigint;

    //a description of how to use this proof
    @Transform(({value}) => value as ProofUsage)
    usage: ProofUsage = ProofUsage.SelectionLimit



    public constructor(pad: ElementModP,
                       data: ElementModP,
                       challenge: ElementModQ,
                       response: ElementModQ,
                       constant: bigint,
                       usage: ProofUsage = ProofUsage.SelectionLimit) {
        this.pad = pad;
        this.data = data;
        this.challenge = challenge;
        this.response = response;
        this.constant = constant;
        this.usage = usage;
    }

    public is_valid(message: ElGamalCiphertext, k: ElementModP, q: ElementModQ): boolean {
        const [alpha, beta] = [message.pad, message.data];
        const a:ElementModP = this.pad;
        const b:ElementModP = this.data;
        const c:ElementModQ = this.challenge;
        const v:ElementModQ = this.response;
        const constant: bigint = this.constant;
        const in_bounds_alpha:boolean = alpha.is_valid_residue();
        const in_bounds_beta:boolean = beta.is_valid_residue();
        const in_bounds_a:boolean = a.is_valid_residue();
        const in_bounds_b:boolean = b.is_valid_residue();
        const in_bounds_c:boolean = c.is_in_bounds();
        const in_bounds_v:boolean = v.is_in_bounds();
        const tmp = int_to_q(constant);
        let in_bounds_constant;
        let constant_q;
        if (tmp == null){
            constant_q = ZERO_MOD_Q;
            in_bounds_constant = false;
        } else {
            constant_q = tmp;
            in_bounds_constant = true;
        }

        // this is an arbitrary constant check to verify that decryption will be performant
        // in some use cases this value may need to be increased

        const sane_constant:boolean = 0 <= constant && constant < 1_000_000_000;
        const same_c:boolean = c.equals(hash_elems([q, alpha, beta, a, b]));
        const consistent_gv:boolean = (
            in_bounds_v
            && in_bounds_a
            && in_bounds_alpha
            && in_bounds_c
            // The equation 𝑔^𝑉 = 𝑎𝐴^𝐶 mod 𝑝
            && g_pow_p(v).equals(mult_p(a, pow_p(alpha, c)))
        );

        // The equation 𝑔^𝐿𝐾^𝑣 = 𝑏𝐵^𝐶 mod 𝑝
        const consistent_kv:boolean = in_bounds_constant && mult_p(
            g_pow_p(mult_p(c, constant_q as ElementModQ)), pow_p(k, v)
        ).equals(mult_p(b, pow_p(beta, c)));

        const success = (
            in_bounds_alpha
            && in_bounds_beta
            && in_bounds_a
            && in_bounds_b
            && in_bounds_c
            && in_bounds_v
            && same_c
            && in_bounds_constant
            && sane_constant
            && consistent_gv
            && consistent_kv
        );
        if (!success){
            console.log("in_bounds_alpha: ", in_bounds_alpha, "in_bounds_beta: ", in_bounds_beta, "in_bounds_a: ", in_bounds_a,
            "in_bounds_b: ", in_bounds_b, "in_bounds_c: ", in_bounds_c, "in_bounds_v: ", in_bounds_v, "in_bounds_constant: ", in_bounds_constant,
            "sane_constant: ", sane_constant, "same_c: ", same_c, "consistent_gv: ", consistent_gv, "consistent_kv: ", consistent_kv,
            "k: ", k);
        }

        return success
    }

}

export function make_disjunctive_chaum_pedersen(
    message: ElGamalCiphertext,
    r: ElementModQ,
    k: ElementModP,
    q: ElementModQ,
    seed: ElementModQ,
    plaintext: number): DisjunctiveChaumPedersenProof {
    if (plaintext == 0){
        return make_disjunctive_chaum_pedersen_zero(message, r, k, q, seed);
    } else {
        return make_disjunctive_chaum_pedersen_one(message, r, k, q, seed);
    }
}

export function make_disjunctive_chaum_pedersen_zero(
    message: ElGamalCiphertext,
    r: ElementModQ,
    k: ElementModP,
    q: ElementModQ,
    seed: ElementModQ): DisjunctiveChaumPedersenProof{

    const [alpha, beta] = [message.pad, message.data];
    // Pick three random numbers in Q.
    const nonces = new Nonces(seed, "disjoint-chaum-pedersen-proof");

    const c1 = nonces.get(0);
    const v = nonces.get(1);
    const u0 = nonces.get(2);

    // # Compute the NIZKP
    const a0 = g_pow_p(u0);
    const b0 = pow_p(k, u0);
    const a1 = g_pow_p(v);
    const b1 = mult_p(pow_p(k, v), g_pow_p(c1));
    const c = hash_elems([q, alpha, beta, a0, b0, a1, b1]);
    const c0 = a_minus_b_q(c, c1);
    const v0 = a_plus_bc_q(u0, c0, r);
    const v1 = a_plus_bc_q(v, c1, r);
    return new DisjunctiveChaumPedersenProof(a0, b0, a1, b1, c0, c1, c, v0, v1);
}

export function make_disjunctive_chaum_pedersen_one(
    message: ElGamalCiphertext,
    r: ElementModQ,
    k: ElementModP,
    q: ElementModQ,
    seed: ElementModQ): DisjunctiveChaumPedersenProof{
    const [alpha, beta] = [message.pad, message.data];
    // Pick three random numbers in Q.
    const nonces = new Nonces(seed, "disjoint-chaum-pedersen-proof");
    const w = nonces.get(0);
    const v = nonces.get(1);
    const u1 = nonces.get(2);

    // # Compute the NIZKP
    const a0 = g_pow_p(v);
    const b0 = mult_p(pow_p(k, v), g_pow_p(w));
    const a1 = g_pow_p(u1);
    const b1 = pow_p(k, u1);
    const c = hash_elems([q, alpha, beta, a0, b0, a1, b1]);
    const c0 = negate_q(w);
    const c1 = add_q(c, w);
    const v0 = a_plus_bc_q(v, c0, r);
    const v1 = a_plus_bc_q(u1, c1, r);

    return new DisjunctiveChaumPedersenProof(a0, b0, a1, b1, c0, c1, c, v0, v1);
}

export function make_constant_chaum_pedersen(
    message: ElGamalCiphertext,
    constant: bigint,
    r: ElementModQ,
    k: ElementModP,
    seed: ElementModQ,
    base_hash: ElementModQ,
): ConstantChaumPedersenProof{
    const [alpha, beta] = [message.pad, message.data];

    // Pick one random number in Q.
    const nonce = new Nonces(seed, "constant-chaum-pedersen-proof")
    const u = nonce.get(0);

    const a = g_pow_p(u);  // 𝑔^𝑢𝑖 mod 𝑝
    const b = pow_p(k, u);  // 𝐴^𝑢𝑖 mod 𝑝
    const c = hash_elems([base_hash, alpha, beta, a, b]);  // sha256(𝑄', A, B, a, b)
    const v = a_plus_bc_q(u, c, r);

    return new ConstantChaumPedersenProof(a, b, c, v, constant);
}

export class ChaumPedersenProofGeneric {
    // General-purpose Chaum-Pedersen proof object, demonstrating that the prover knows the exponent
    // x for two tuples (g, g^x) and (h, h^x). This is used as a component in other proofs.

    a: ElementModP;
    // a = g^w

    b: ElementModP;
    // b = h^w

    c: ElementModQ;
    // c = hash(a, b)

    r: ElementModQ;
    // r = w + xc

    public constructor(a: ElementModP, b: ElementModP, c: ElementModQ, r: ElementModQ) {
        this.a = a;
        this.b = b;
        this.c = c;
        this.r = r;
    }

    public is_valid(
        g: ElementModP,
        gx: ElementModP,
        h: ElementModP,
        hx: ElementModP,
        base_hash: ElementModQ | null,
        check_c = true): boolean {
        const in_bounds_a = this.a.is_valid_residue();
        const in_bounds_b = this.b.is_valid_residue();
        const in_bounds_g = g.is_valid_residue();
        const in_bounds_gx = gx.is_valid_residue();
        const in_bounds_h = h.is_valid_residue();
        const in_bounds_hx = hx.is_valid_residue();

        const hash_good = (this.c.equals(hash_elems([base_hash, this.a, this.b]))) || (!check_c);

        const agxc = mult_p(this.a, pow_p(gx, this.c));  // should yield g^{w + xc}
        const gr = pow_p(g, this.r);  // should also yield g^{w + xc}

        const good_g = agxc.equals(gr);

        const bhxc = mult_p(this.b, pow_p(hx, this.c));
        const hr = pow_p(h, this.r);

        const good_h = bhxc.equals(hr);

        const success = (
            hash_good
            && in_bounds_a
            && in_bounds_b
            && in_bounds_g
            && in_bounds_gx
            && in_bounds_h
            && in_bounds_hx
            && good_g
            && good_h
        );
        if (!success){
            console.log("hash_good: ", hash_good, "in_bounds_a: ", in_bounds_a, "in_bounds_b: ", in_bounds_b,
            "in_bounds_g: ", in_bounds_g, "in_bounds_gx: ", in_bounds_gx, "in_bounds_h: ", in_bounds_h, "in_bounds_hx: ", in_bounds_hx,
            "good_g: ", good_g, "good_h: ", good_h);
        }

        return success
    }

}

export function make_chaum_pedersen_generic(
    g: ElementModP,
    h: ElementModP,
    x: ElementModQ,
    seed: ElementModQ,
    base_hash: ElementModQ | null,
): ChaumPedersenProofGeneric {
    const nonce = new Nonces(seed, "generic-chaum-pedersen-proof");
    const w = nonce.get(0);
    const a = pow_p(g, w);
    const b = pow_p(h, w);
    const c = hash_elems([base_hash, a, b]);
    const r = a_plus_bc_q(w, x, c);

    return new ChaumPedersenProofGeneric(a, b, c, r);
}

export function make_fake_chaum_pedersen_generic(
    g: ElementModP,
    gx: ElementModP,
    h: ElementModP,
    hx: ElementModP,
    c: ElementModQ,
    seed: ElementModQ
): ChaumPedersenProofGeneric {
    const nonce = new Nonces(seed, "generic-chaum-pedersen-proof");
    const r = nonce.get(0);
    const gr = pow_p(g, r);
    const hr = pow_p(h, r);
    const a = mult_p(gr, mult_inv_p(pow_p(gx, c)));
    const b = mult_p(hr, mult_inv_p(pow_p(hx, c)));

    return new ChaumPedersenProofGeneric(a, b, c, r);
}

export class ChaumPedersenDecryptionProof {
    proof: ChaumPedersenProofGeneric;

    public constructor(proof: ChaumPedersenProofGeneric) {
      this.proof = proof;
    }

    public is_valid(
        plaintext: bigint,
        ciphertext: ElGamalCiphertext,
        public_key: ElementModP,
        base_hash: ElementModQ | null
    ): boolean {
        const plaintext_p = int_to_p(plaintext);
        if (plaintext_p == undefined){
          return false;
        }

        const g_exp_plaintext = g_pow_p(plaintext_p);
        const blinder = mult_p(ciphertext.data, mult_inv_p(g_exp_plaintext));

        const valid_proof = this.proof.is_valid(
            int_to_p_unchecked(G),
            public_key,
            ciphertext.pad,
            blinder,
            base_hash,
          true,
        );
        if (!valid_proof) {
            console.log("plaintext: ", plaintext, "ciphertext: ", ciphertext, "public_key: ", public_key,
            "proof: ", this.proof);
        }
        return valid_proof;
    }
}

export function make_chaum_pedersen_decryption_proof(
    ciphertext: ElGamalCiphertext,
    secret_key: ElementModQ,
    seed: ElementModQ,
    base_hash: ElementModQ | null
): ChaumPedersenDecryptionProof {
    return new ChaumPedersenDecryptionProof(
        make_chaum_pedersen_generic(
            int_to_p_unchecked(G), ciphertext.pad, secret_key, seed, base_hash
        )
    );
}
