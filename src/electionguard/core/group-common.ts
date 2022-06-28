import {ElectionConstants} from './constants';
import {CryptoHashableString} from './hash';
import {UInt256} from './uint256';

export const BIG_ZERO = BigInt('0');
export const BIG_ONE = BigInt('1');
export const BIG_TWO = BigInt('2');

/**
 * {@link ElementModP} and {@link ElementModQ} both implement this
 * interface, which is useful for functions and methods that can
 * work on either type.
 */
export interface Element extends CryptoHashableString {
  /** Fetches the GroupContext used by this element. */
  get context(): GroupContext;

  /** Converts from the internal representation to a regular JS bigint. */
  toBigint(): bigint;

  /** Converts from the internal representation to a big-endian Uint8Array. */
  toBytes(): Uint8Array;

  /**
   * Validate that the element is actually within the bounds of
   * [0,max). Returns true if all is good, false if something's
   * wrong.
   */
  isInBounds(): boolean;

  /**
   * Validate that the element is actually within the bounds of
   * [1,max). Returns true if all is good, false if something's
   * wrong.
   */
  isInBoundsNoZero(): boolean;

  /** Returns whether the element is zero.  */
  isZero(): boolean;

  /** Returns a hexidecimal representation of the element. */
  toHex(): string;
}

/**
 * General-purpose holder of elements in [0, Q). The constructor
 * and concrete type are not exposed. Instead use the helper
 * functions, like {@link GroupContext[createElementModQ]},
 * which will check for errors.
 */
export interface ElementModQ extends Element {
  equals(other: ElementModQ): boolean;
  greaterThan(other: ElementModQ): boolean;
  greaterThanOrEqual(other: ElementModQ): boolean;
  lessThan(other: ElementModQ): boolean;
  lessThanOrEqual(other: ElementModQ): boolean;
  toString(): string;
  toUInt256(): UInt256;
}

/**
 * General-purpose holder of elements in [0, P). The constructor
 * and concrete type are not exposed. Instead use the helper
 * functions, like {@link GroupContext[createElementModP]},
 * which will check for errors.
 */
export interface ElementModP extends Element {
  equals(other: ElementModP): boolean;
  toString(): string;
  greaterThan(other: ElementModP): boolean;
  greaterThanOrEqual(other: ElementModP): boolean;
  lessThan(other: ElementModP): boolean;
  lessThanOrEqual(other: ElementModP): boolean;

  /**
   * Validate that this element is in the subgroup reachable
   * from the generator.
   */
  isValidResidue(): boolean;

  /**
   * Creates a new instance of this element where the {@link powP} function will use the acceleration
   * possible with {@link PowRadix} to run faster.
   */
  acceleratePow(): ElementModP;

  /** Internal implementation of powP(), which might or might not be accelerated.  */
  powP(exponent: ElementModQ | number): ElementModP;

  /** Converts to Montgomery form, allowing for faster modular multiplication. */
  toMontgomeryElementModP(): MontgomeryElementModP;
}

/**
 * Montgomery form of an {@link ElementModP}. Note the very limited set of methods. Convert back to
 * a regular {@link ElementModP} for anything other than multiplication.
 */
export interface MontgomeryElementModP {
  /** Modular multiplication. */
  multiply(other: MontgomeryElementModP): MontgomeryElementModP;

  /** Convert back to the normal representation. */
  toElementModP(): ElementModP;

  /** Fetches the GroupContext used by this element. */
  get context(): GroupContext;
}

/**
 * A GroupContext wraps up a lot of state for managing elements of the
 * cryptographic groups that we use in ElectionGuard. It also allows
 * us to manage and differentiate between incompatible groups (e.g.,
 * 3072-bits versus 4096-bits).
 *
 * While the GroupContext defines a bunch of methods for things like
 * adding and multiplying members of a group, external code shouldn't
 * use those methods. Instead, use the top-level functions defined by
 * group-common.ts at the bottom of the file. Every Element knows its
 * internal context, so for the most part, you can just call functions
 * like addQ() and all the compatibility checks and context management
 * will be handled inside.
 *
 * You will need the GroupContext for the various "create" methods
 * that allow you to go from external strings or numbers into Elements.
 * You'll also see that the GroupContext is necessary in a few other
 * places, like the property-based testing value generators.
 */
export interface GroupContext {
  /**
   * Textual description of the group (e.g., "BigInt-4096 GroupContext",
   * or "HACL-WASM-3072 GroupContext").
   */
  name: string;

  /**
   * Creates a new {@link ElementModQ} from a hexadecimal (base16)
   * string. Assumes no leading '0x'.
   */
  createElementModQFromHex: (value: string) => ElementModQ | undefined;

  /**
   * Creates a new ElementModQ from a bigint, a string (base 10, or a
   * number. Returns undefined if the input is not well-formed or is out of
   * the desired range of [0, Q).
   */
  createElementModQ: (
    value: bigint | string | number
  ) => ElementModQ | undefined;

  /**
   * Creates a new ElementModQ from a bigint, a string (base 10), or a number.
   * If the number is out of range, it will be wrapped to [minimum, Q). If the
   * input isn't a well-defined number, the result will be zero.
   */
  createElementModQSafe: (
    value: bigint | string | number,
    minimum?: number
  ) => ElementModQ;

  /**
   * Creates a new {@link ElementModP} from a hexadecimal (base16)
   * string. Assumes no leading '0x'.
   */
  createElementModPFromHex: (value: string) => ElementModP | undefined;

  /**
   * Creates a new ElementModP from a bigint, a string (base 10),
   * or a number. Returns undefined if the input is not well-formed
   * or is out of the desired range of [0, P).
   */
  createElementModP: (
    value: bigint | string | number
  ) => ElementModP | undefined;

  /**
   * Creates a new ElementModP from a bigint, a string (base 10
   * or prefixed with "0x" for base16), or a number. If the number
   * is out of range, it will be wrapped (in an undefined manner)
   * to [0, P).
   */
  createElementModPSafe: (value: bigint | string | number) => ElementModP;

  electionConstants: ElectionConstants;

  ZERO_MOD_Q: ElementModQ;
  ONE_MOD_Q: ElementModQ;
  TWO_MOD_Q: ElementModQ;
  ZERO_MOD_P: ElementModP;
  ONE_MOD_P: ElementModP;
  TWO_MOD_P: ElementModP;
  G_MOD_P: ElementModP;
  G_SQUARED_MOD_P: ElementModP;
  G_INVERSE_MOD_P: ElementModP;

  P: bigint;
  Q: bigint;
  G: bigint;

  /** Computes the sum, mod q, of two {@link ElementModQ} values. */
  addQ: (a: ElementModQ, b: ElementModQ) => ElementModQ;

  /** Computes the subtraction, mod q, of two {@link ElementModQ} values. */
  subQ: (a: ElementModQ, b: ElementModQ) => ElementModQ;

  /** Computes the product, mod q, of two {@link ElementModQ} values. */
  multQ: (a: ElementModQ, b: ElementModQ) => ElementModQ;

  /** Computes the multiplicative inverse, mod q, of an {@link ElementModQ}. */
  multInvQ: (a: ElementModQ) => ElementModQ;

  /** Computes the addtive inverse, mod q, of an {@link ElementModQ}. */
  negateQ: (a: ElementModQ) => ElementModQ;

  /**
   * Computes the division (really, multiplication by the modular
   * inverse), mod q, of two {@link ElementModQ} values.
   */
  divQ: (a: ElementModQ, b: ElementModQ) => ElementModQ;

  /** Uses a source of secure randomness to derive a fresh ElementModQ.  */
  randQ: (minimum?: number) => ElementModQ;

  /** Computes base^exponent mod p. */
  powP: (base: ElementModP, exponent: ElementModQ | number) => ElementModP;

  /** Computes generator^exponent mod p. */
  gPowP: (exponent: ElementModQ | number) => ElementModP;

  /** Computes the product, mod p, of two {@link ElementModP} values. */
  multP: (a: ElementModP, b: ElementModP) => ElementModP;

  /**
   * Computes the multiplicative inverse, mod p, of an {@link ElementModP}.
   */
  multInvP: (a: ElementModP) => ElementModP;

  /**
   * Computes the division (really, multiplication by the modular
   * inverse), mod p, of two {@link ElementModP} values.
   */
  divP: (a: ElementModP, b: ElementModP) => ElementModP;

  /**
   * Computes the discrete log, in the base of the generator.
   * If it cannot find a solution, it returns undefined.
   */
  dLogG: (e: ElementModP) => number | undefined;
}

export function compatibleContextOrFail(...elements: Element[]): GroupContext {
  if (elements.length === 0) {
    throw Error('Cannot call with zero arguments');
  }

  const allNames = elements.map(x => x.context.name);
  const allNamesSame = allNames.every(x => x === allNames[0]);

  if (allNamesSame) {
    return elements[0].context;
  } else throw Error(`Incompatible contexts: ${allNames.join(', ')}`);
}

// Why do we have functions inside the context and also have identically-named functions
// outside the context? The ones on the inside assume that their arguments are compatible,
// while these will raise errors if they're incompatible.

// What would be really nice is if we could use operator overloading, so "a + b" would
// desugar down to "addQ(a, b)", but alas, TypeScript doesn't have a feature like this.

/** Computes the sum, mod q, of two {@link ElementModQ} values. */
export function addQ(...elements: ElementModQ[]): ElementModQ {
  if (elements.length === 0) {
    throw new Error('addQ requires at least one argument');
  }
  const context = compatibleContextOrFail(...elements);
  const sum = elements
    .slice(1)
    .reduce((prev, next) => context.addQ(prev, next), elements[0]);
  return sum;
}

/** Computes the subtraction, mod q, of two {@link ElementModQ} values. */
export function subQ(a: ElementModQ, b: ElementModQ): ElementModQ {
  return compatibleContextOrFail(a, b).subQ(a, b);
}

/** Computes the product, mod q, of two {@link ElementModQ} values. */
export function multQ(a: ElementModQ, b: ElementModQ): ElementModQ {
  return compatibleContextOrFail(a, b).multQ(a, b);
}

/** Computes the multiplicative inverse, mod q, of an {@link ElementModQ}. */
export function multInvQ(a: ElementModQ): ElementModQ {
  return a.context.multInvQ(a);
}

/** Computes the addtive inverse, mod q, of an {@link ElementModQ}. */
export function negateQ(a: ElementModQ): ElementModQ {
  return a.context.negateQ(a);
}

/**
 * Computes the division (really, multiplication by the modular
 * inverse), mod q, of two {@link ElementModQ} values.
 */
export function divQ(a: ElementModQ, b: ElementModQ): ElementModQ {
  return compatibleContextOrFail(a, b).divQ(a, b);
}

/** Computes base^exponent mod p. */
export function powP(
  base: ElementModP,
  exponent: ElementModQ | number
): ElementModP {
  if (typeof exponent === 'number') {
    return base.context.powP(base, exponent);
  } else {
    return compatibleContextOrFail(base, exponent).powP(base, exponent);
  }
}

/** Computes the product, mod p, of two {@link ElementModP} values. */
export function multP(a: ElementModP, b: ElementModP): ElementModP {
  return compatibleContextOrFail(a, b).multP(a, b);
}

/**
 * Computes the multiplicative inverse, mod p, of an {@link ElementModP}.
 */
export function multInvP(a: ElementModP): ElementModP {
  return a.context.multInvP(a);
}

/**
 * Computes the division (really, multiplication by the modular
 * inverse), mod p, of two {@link ElementModP} values.
 */
export function divP(a: ElementModP, b: ElementModP): ElementModP {
  return compatibleContextOrFail(a, b).divP(a, b);
}

/**
 * Computes the discrete log, in the base of the generator.
 * If it cannot find a solution, it returns undefined.
 */
export function dLogG(e: ElementModP): number | undefined {
  return e.context.dLogG(e);
}
