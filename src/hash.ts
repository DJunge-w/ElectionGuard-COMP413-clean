import {
  ElementModPOrQ,
  ElementModQ,
  Q_MINUS_ONE,
  int_to_q_unchecked,
  ElementModP} from "./group";

import * as crypto from "crypto";
// import { Language } from "./manifest";

/**
 * Denotes Hashable
 */
export abstract class CryptoHashable {
  /**
   * Generates a hash given the fields on the implementing instance.
   */
  abstract crypto_hash(): ElementModQ;
}

/**
 * Checkable version of crypto hash
 */
export abstract class CryptoHashCheckable {
  /**
   * Generates a hash with a given seed that can be checked later
   * against the seed and class metadata.
   * @param seed_hash the seed used to generate a hash.
   */
  abstract crypto_hash_with(seed_hash: ElementModQ): ElementModQ;
}

// All the "atomic" types that we know how to hash.
export type CRYPTO_HASHABLE_T = CryptoHashable | ElementModPOrQ | string | number | undefined | null ;

export type CRYPTO_HASHABLE_ALL = CRYPTO_HASHABLE_T[] | CRYPTO_HASHABLE_T | CRYPTO_HASHABLE_ALL[];

export function tohex_for_hash(x:ElementModQ|ElementModP):string {
  let hash_me = '';
  if (x.to_hex().startsWith('00')) {
    hash_me = x.to_hex().substring(2).toUpperCase();
  } else {
    hash_me = x.to_hex().toUpperCase();
  }
  return hash_me
}

export function hash_elem(x:CRYPTO_HASHABLE_T):string {
    let hash_me = 'null';
    if (x instanceof ElementModQ || x instanceof ElementModP) {
      if (x.elem != BigInt(0)) {
        hash_me = tohex_for_hash(x);
      }
    } else if (x instanceof CryptoHashable) {
      hash_me = tohex_for_hash(x.crypto_hash());
    } else if (typeof x === "string") {
      hash_me = x;
    } else if (typeof x === "number") {
      if (x!= 0) {
        hash_me = x.toString();
      } else {
        hash_me = '0'
        // john-adams-selection 0 adams hash wrong result
      }
    }
    return hash_me;
}

/**
 * Given zero or more elements, calculate their cryptographic hash
 * using SHA256. Allowed element types are `ElementModP`, `ElementModQ`,
 * `str`, or `int`, anything implementing `CryptoHashable`, and lists
 * or optionals of any of those types.
 * @param a Zero or more elements of any of the accepted types.
 * return A cryptographic hash of these elements, concatenated.
 */
export function hash_elems(a: CRYPTO_HASHABLE_ALL): ElementModQ {
  const hashme_lst = [];
  const h = crypto.createHash('sha256');
  h.update("|", "utf-8");
  let hash_me:string;

  if (!(a instanceof(Array))) {
    hash_me = hash_elem(a as CRYPTO_HASHABLE_T);
    h.update(hash_me + "|", "utf-8")
  } else {
  for (const x of a as Array<CRYPTO_HASHABLE_T>) {
    if (Array.isArray(x)) {
      if (x.length === 0) {
        hash_me = "null";
      } else {
        const tmp = hash_elems(x);
        hash_me = tohex_for_hash(tmp);
      }
    } else if ((x === null || x === undefined)) {
      hash_me = "null";
    } else {
      hash_me = hash_elem(x);
    }
    hashme_lst.push(hash_me);

    h.update(hash_me + "|", "utf-8")
  }
}
  const tempRsltForDebug = BigInt('0x' + h.digest('hex').toString()).toString(10);
  const hash_rslt = int_to_q_unchecked(
    BigInt(tempRsltForDebug) % Q_MINUS_ONE);
    /// just for testing!!
  //   const hash_newlist:string[] = ['FEF3', '7F79', '03', '1', '1', '3793',]
  //   const h1 = crypto.createHash('sha256');
  //    h1.update("|", "utf-8");
  //    for (const element of hash_newlist) {
  //      h1.update(element + '|', "utf-8");
  //    }
  //   console.log("hash_rslt!!!!")
  //   const tempRsltForDebug = BigInt('0x' + h1.digest('hex').toString()).toString(10);
  //   const hash_rslt = int_to_q_unchecked(
  //     BigInt(tempRsltForDebug) % Q_MINUS_ONE);
  //   console.log(hash_rslt)
  // // const hash_rslt = int_to_q_unchecked(1n);
  return hash_rslt;
}
