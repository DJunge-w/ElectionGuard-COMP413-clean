import {discrete_log} from "./dlog"
import {
  ElementModQ,
  ElementModP,
  g_pow_p,
  mult_p,
  mult_inv_p,
  pow_p,
  ZERO_MOD_Q,
  TWO_MOD_Q,
  int_to_q,
  rand_range_q, ElementModPOrQorInt,
} from "./group"

import {hash_elems} from "./hash"
// import {log_error} from "./logs"
import {
  flatmap_optional,
  get_optional
} from "./utils"
import {Transform} from "class-transformer";

type ElGamalPublicKey = ElementModP;
type ElGamalSecretKey = ElementModQ;

/**
 * A tuple of an ElGamal secret key and public key.
 */
export class ElGamalKeyPair {
  secret_key: ElGamalSecretKey;
  public_key: ElGamalPublicKey;

  constructor(secret_key: ElGamalSecretKey, public_key: ElGamalPublicKey) {
    this.secret_key = secret_key;
    this.public_key = public_key;
  }

}

/**
 * An "exponential ElGamal ciphertext" (i.e., with the plaintext in the exponent to allow for
 * homomorphic addition). Create one with `elgamal_encrypt`. Add them with `elgamal_add`.
 * Decrypt using one of the supplied instance methods.
 */
export class ElGamalCiphertext {
  //Pad or alpha
  @Transform(({value}) => new ElementModP(BigInt("0x"+value)))
  pad: ElementModP;
  //encrypted data or beta
  @Transform(({value}) => new ElementModP(BigInt("0x"+value)))
  data: ElementModP;

  constructor(pad: ElementModP, data: ElementModP) {
    this.pad = pad;
    this.data = data;
  }
  /**
   * Decrypts an ElGamal ciphertext with a "known product"
   * (the blinding factor used in the encryption).
   * @param product the blinding factor used in the encryption
   */
  public decrypt_known_product(product: ElementModP): bigint {
    return discrete_log(mult_p(this.data, mult_inv_p(product)));
  }

  /**
   * Decrypt an ElGamal ciphertext using a known ElGamal secret key.
   * @param secret_key The corresponding ElGamal secret key.
   * Return A plaintext message.
   */
  public decrypt(secret_key: ElementModQ): bigint {

    return this.decrypt_known_product(pow_p(this.pad, secret_key));
  }

  /**
   * Decrypt an ElGamal ciphertext using a known nonce and the ElGamal public key.
   * @param public_key The corresponding ElGamal public key.
   * @param nonce The secret nonce used to create the ciphertext.
   * Return A plaintext message.
   */
  public decrypt_known_nonce(public_key: ElementModP,
                             nonce: ElementModQ): bigint{
    return this.decrypt_known_product(pow_p(public_key, nonce));
  }

  /**
   * Computes a cryptographic hash of this ciphertext.
   */
  public crypto_hash():ElementModQ {
    return hash_elems([this.pad, this.data]);
  }

}

/**
 * Given an ElGamal secret key (typically, a random number in [2,Q)), returns
 * an ElGamal keypair, consisting of the given secret key a and public key g^a.
 * @param a A secret key
 */
export function elgamal_keypair_from_secret(a: ElementModQ)
  : ElGamalKeyPair | null {
  const secret_key_int: bigint = a.to_int();
  if (secret_key_int < 2) {
    // log_error("ElGamal secret key needs to be in [2,Q).");
    return null;
  }
  return new ElGamalKeyPair(a, g_pow_p(a));
}

/**
 * Create a random elgamal keypair
 * return random elgamal key pair
 */
export function elgamal_keypair_random(): ElGamalKeyPair {
  return get_optional(elgamal_keypair_from_secret(rand_range_q(TWO_MOD_Q)));
}

export function elgamal_encrypt
(m: bigint, nonce: ElementModQ,
 public_key: ElementModPOrQorInt): ElGamalCiphertext | null | undefined {
  if (nonce === ZERO_MOD_Q) {
    // log_error("ElGamal encryption requires a non-zero nonce");
    return null;
  }
  // if (m < 0) {
  //   log_error("Can't encrypt a negative message");
  //   throw Error("Can't encrypt a negative message");
  // }
  // if (m >= Q) {
  //   log_error("Can't encrypt a message bigger than Q");
  //   throw Error("Can't encrypt a message bigger than Q");
  // }
  // let pk;
  // if (public_key instanceof ElGamalKeyPair) {
  //   pk = public_key.public_key;
  // } else {
  //   pk = public_key;
  // }
  return flatmap_optional(int_to_q(m), (e:ElementModQ ) => new ElGamalCiphertext(g_pow_p(nonce), mult_p(g_pow_p(e), pow_p(public_key, nonce))));
}

export function elgamal_add(...ciphertexts: ElGamalCiphertext[]): ElGamalCiphertext {
  if (ciphertexts.length == 0) {
    throw new Error("Must have one or more ciphertexts for elgamal_add");
  }

  let result: ElGamalCiphertext = ciphertexts[0];
  for (let i = 1; i < ciphertexts.length; i++) {
    const c:ElGamalCiphertext = ciphertexts[i];
    result = new ElGamalCiphertext(mult_p(result.pad, c.pad), mult_p(result.data, c.data));
  }
  return result;
}

