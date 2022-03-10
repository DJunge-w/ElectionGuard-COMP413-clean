import {
  ElementModQ,
    ElementModP,
    g_pow_p,
    G,
    P,
    Q,
    ZERO_MOD_Q,
    TWO_MOD_Q,
    ONE_MOD_Q,
    ONE_MOD_P,} from './group';
import { elements_mod_q_no_zero} from './groupUtils';
// import {hash_elems} from './hash';
import {ElGamalKeyPair,
    ElGamalCiphertext,
    elgamal_encrypt,
    elgamal_add,
    elgamal_keypair_from_secret,
    elgamal_keypair_random
} from './elgamal';
import {get_optional} from "./utils";
// import exp from 'constants';

describe("TestElgamal", () => {
    test('test_simple_elgamal_encryption_decryption', () => {
        const nonce = ONE_MOD_Q;
        const secret_key = TWO_MOD_Q
        const keypair:ElGamalKeyPair| null | undefined = elgamal_keypair_from_secret(secret_key);
        const public_key = get_optional(keypair).public_key;
        expect(public_key.to_int()).toBeLessThan(P);


        const elem:ElementModP = g_pow_p(ZERO_MOD_Q);
        expect(elem.equals(ONE_MOD_P)).toBe(true); // g^0 == 1

        const ciphertext:ElGamalCiphertext| null | undefined = elgamal_encrypt(0n, nonce, get_optional(keypair).public_key);
        expect(G).toBe(get_optional(ciphertext).pad.to_int());
        expect(get_optional(ciphertext).pad.to_int() ** secret_key.to_int() % P).toBe(public_key.to_int() ** nonce.to_int() % P);
        expect(get_optional(ciphertext).data.to_int()).toBe(public_key.to_int() ** nonce.to_int() % P);

        const plaintext:bigint = get_optional(ciphertext).decrypt(get_optional(keypair).secret_key);

        expect(plaintext).toBe(0n);
    });

    test('test_elgamal_encrypt_requires_nonzero_nonce', () => {
        const max = 100;
        const min = 0;
        const message = BigInt(Math.floor(Math.random() * (max - min + 1) + min));
        const keypair:ElGamalKeyPair|null = elgamal_keypair_from_secret(elements_mod_q_no_zero());
        expect(elgamal_encrypt(message, ZERO_MOD_Q, get_optional(keypair).public_key)).toBe(null);
    });

    test('test_elgamal_keypair_from_secret_requires_key_greater_than_one', () => {
        expect(elgamal_keypair_from_secret(ZERO_MOD_Q)).toBe(null);
        expect(elgamal_keypair_from_secret(ONE_MOD_Q)).toBe(null);

    });

    test('test_elgamal_encryption_decryption_inverses', () => {
        const max = 100;
        const min = 0;
        const message = BigInt(Math.floor(Math.random() * (max - min + 1) + min));
        const keypair:ElGamalKeyPair|null = elgamal_keypair_from_secret(elements_mod_q_no_zero());
        const nonce:ElementModQ|null = elements_mod_q_no_zero();

        // to avoid non-used issue
        // console.log(message,keypair,nonce);

        const ciphertext = elgamal_encrypt(message, nonce, get_optional(keypair).public_key)
        const plaintext:bigint = get_optional(ciphertext).decrypt(get_optional(keypair).secret_key);
        expect(plaintext).toBe(message);
    });

    test('test_elgamal_encryption_decryption_with_known_nonce_inverses', () => {
        const max = 100;
        const min = 0;
        const message = BigInt(Math.floor(Math.random() * (max - min + 1) + min));
        const keypair:ElGamalKeyPair|null = elgamal_keypair_from_secret(elements_mod_q_no_zero());
        const nonce:ElementModQ|null = elements_mod_q_no_zero();

        // to avoid non-used issue
        // console.log(message,keypair,nonce);

        const ciphertext = elgamal_encrypt(message, nonce, get_optional(keypair).public_key)
        const plaintext:bigint = get_optional(ciphertext).decrypt_known_nonce(get_optional(keypair).public_key, nonce);
        expect(plaintext).toBe(message);
    });

    test('test_elgamal_generated_keypairs_are_within_range', () => {
        const keypair:ElGamalKeyPair|null = elgamal_keypair_from_secret(elements_mod_q_no_zero());
        expect(get_optional(keypair).public_key.to_int()).toBeLessThan(P);
        expect(get_optional(keypair).secret_key.to_int()).toBeLessThan(Q);
        expect(g_pow_p(get_optional(keypair).secret_key).equals(get_optional(keypair).public_key)).toBe(true);
    });

    test('test_elgamal_add_homomorphic_accumulation_decrypts_successfully', () => {
        const r1 = elements_mod_q_no_zero();
        const r2 = elements_mod_q_no_zero();
        const max = 100;
        const min = 0;
        const m1 = BigInt(Math.floor(Math.random() * (max - min + 1) + min));
        const m2 = BigInt(Math.floor(Math.random() * (max - min + 1) + min));
        const keypair:ElGamalKeyPair|null = elgamal_keypair_from_secret(elements_mod_q_no_zero());

        const c1 =  elgamal_encrypt(m1, r1, get_optional(keypair).public_key);
        const c2 =  elgamal_encrypt(m2, r2, get_optional(keypair).public_key);
        const c_sum = elgamal_add(get_optional(c1), get_optional(c2));

          // to avoid non-used issue
          // console.log(c_sum);
        const total = c_sum.decrypt(get_optional(keypair).secret_key);
        expect(total).toBe(m1 + m2);
    });

    test('test_elgamal_add_requires_args', () => {
        //console.assert does not throw an AssertionError (except in Node.js), meaning that this method is incompatible with most testing frameworks and that code execution will not break on a failed assertion.
        // TODO: add manual defined error in elgamal.
        expect(() => {elgamal_add()}).toThrowError();
    });


    test('test_elgamal_keypair_produces_valid_residue', () => {
        let e = elements_mod_q_no_zero();
        if (e.equals(ONE_MOD_Q)) {
            e = TWO_MOD_Q;
        }
        const keypair:ElGamalKeyPair|null = elgamal_keypair_from_secret(e);
        expect(get_optional(keypair).public_key.is_valid_residue()).toBe(true);
    });


    test('test_elgamal_keypair_random', () => {
        let e = elements_mod_q_no_zero();
        if (e == ONE_MOD_Q) {
            e = TWO_MOD_Q;
        }
        const random_keypair = elgamal_keypair_random();
        const random_keypair_two = elgamal_keypair_random();
        expect(random_keypair).toBeDefined();
        expect(random_keypair.public_key).toBeDefined();
        expect(random_keypair.secret_key).toBeDefined();
        expect(random_keypair != random_keypair_two).toBeTruthy();

    });
});
