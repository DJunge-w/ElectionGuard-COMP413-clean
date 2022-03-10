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
} from './group_sjcl';
import { elements_mod_q_no_zero} from './groupUtils_sjcl';
// import {hash_elems} from './hash';
import {
  ElGamalKeyPair,
  // ElGamalCiphertext,
  elgamal_encrypt,
  // elgamal_add,
  elgamal_keypair_from_secret, ElGamalCiphertext,
  // elgamal_keypair_random
} from './elgamal_sjcl';
// import * as sjcl from 'sjcl';
import {get_optional} from "./utils";
// import exp from 'constants';
// import {PowRadixOption} from './powRadix'

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

    // const n1 = "f10853b38e67ed882bc0284b8e71581469806699e8a028a19cd8cac913a3f8b859ee0999833886f13987ecf4ed3a11cf6aabd0b074531f5ef338f624e62429ff";
    // const n2 = "d978cfde1678dc8ce9dab4bfe2e1fa8be09a5668cd8e607cc24f28e440495c7f4b5317d6533e3fb232ebce63fab872ece25935a5cacc5cb8a94b5";
    // const five = "5";
    //
    // const a = new sjcl.bn(n1);
    // const b = new sjcl.bn(n2);
    // let c = a.sub(b);
    // c = a.mod(b);
    // c = a.mul(b);
    // c = a.add(b);
    // c = a.powermod(new sjcl.bn(five), b);
    //
    // console.log(c);

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
