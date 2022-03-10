///<reference path="/Users/djunge/Documents/codes/COMP413/ElectionGuard-COMP413-clean/ElectionGuard-COMP413/node_modules/gmp-wasm/dist/types/index.d.ts"/>

import {
  ElementModQ,
  // ElementModP,
  // g_pow_p,
  // G,
  // P,
  // Q,
  // ZERO_MOD_Q,
  // TWO_MOD_Q,
  // ONE_MOD_Q,
  // ONE_MOD_P,
} from './group';
import { elements_mod_q_no_zero} from './groupUtils';
// import {hash_elems} from './hash';
import {
  ElGamalKeyPair,
  // ElGamalCiphertext,
  elgamal_encrypt,
  // elgamal_add,
  elgamal_keypair_from_secret, ElGamalCiphertext,
  // elgamal_keypair_random
} from './elgamal';
// import * as sjcl from 'sjcl';
import {get_optional} from "./utils";
// import exp from 'constants';
// import {PowRadixOption} from './powRadix'
import gmp = require('gmp-wasm');

function measureTimeMillis(f: () => void): number {
  const start = Date.now();
  f();
  const end = Date.now();
  return end - start;
}

/**
 * A simple benchmark that just measures how fast ElGamal encryption runs
 */
describe("BenchmarkElgamal", () => {
  test('test_elgamal_vanilla', () => {
    const N = 10;

    console.log("Initializing benchmark for no acceleration.");
    const max = 1000;
    const min = 0;


    gmp.init().then(({ calculate }) => {
      // calculate() automatically deallocates all objects created within the callback function
      const result = calculate((g) => {
        const six = g.Float(1).add(5);
        return g.Pi().div(six).sin(); // sin(Pi/6) = 0.5
      });
      console.log("gmp-wasm");
      console.log(result);
    });

    // const message = BigInt(Math.floor(Math.random() * (max - min + 1) + min));
    const messages: bigint[] = Array.from(Array(N)).map(() =>{ return BigInt(Math.floor(Math.random() * (max - min + 1) + min))});
    const keypair:ElGamalKeyPair|null = elgamal_keypair_from_secret(elements_mod_q_no_zero());
    const nonce:ElementModQ|null = elements_mod_q_no_zero();

    console.log("Running!");
    console.log(messages);
    const ciphertexts: ElGamalCiphertext[] = [];
    const encryptionTimeMs = measureTimeMillis(() => {
      messages.forEach(message => ciphertexts.push(get_optional(elgamal_encrypt(message, nonce, get_optional(keypair).public_key))))
    });
    const encryptionTime = encryptionTimeMs / 1000.0;
    const plaintexts: bigint[] = [];
    const decryptionTimeMs = measureTimeMillis(() => {
      ciphertexts.forEach(ciphertext => plaintexts.push(get_optional(ciphertext).decrypt(get_optional(keypair).secret_key)))
    });
    const decryptionTime = decryptionTimeMs / 1000.0;
    console.log("ElGamal "+ N / encryptionTime +" encryptions/sec, "+ N / decryptionTime+" decryptions/sec");

    expect(plaintexts).toEqual(messages);

  });
});
