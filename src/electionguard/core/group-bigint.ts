import * as bigintModArith from 'bigint-mod-arith';
import randomBytes from 'randombytes';
import hasArrowFunctionSupport from '@stdlib/assert-has-arrow-function-support';
import hasAsyncAwaitSupport from '@stdlib/assert-has-async-await-support';
import hasBigIntSupport from '@stdlib/assert-has-bigint-support';
import hasClassSupport from '@stdlib/assert-has-class-support';
import hasMapSupport from '@stdlib/assert-has-map-support';
import hasSetSupport from '@stdlib/assert-has-set-support';
import hasUint8ArraySupport from '@stdlib/assert-has-uint8array-support';
import {bigIntToUint8Array, uint8ArrayToBigInt} from './utils';
import {DLogger} from './dlog';
import {
  GroupContext,
  ElementModQ,
  ElementModP,
  MontgomeryElementModP,
  BIG_ZERO,
  BIG_ONE,
  BIG_TWO,
  multP,
  multInvP,
} from './group-common';
import {
  ElectionConstants,
  production3072G,
  production3072P,
  production3072Q,
  production3072R,
  production4096G,
  production4096P,
  production4096Q,
  production4096R,
} from './constants';
import {UInt256} from './uint256';
import {PowRadix} from './powradix';
import * as log from './logging';

// This file exports the functions `bigIntContext3072()` and `bigIntContext4096()`, which return
// instances of the GroupContext interface found in group-common.ts, and which implements all
// the ElementModP and ElementModQ functions that we need for ElectionGuard.

// We're adopting this somewhat excessive separation between interface and implementation,
// even though we don't strictly need it when using bigint, because we need something significantly
// more complicated when working with hacl-wasm, which has to set up a WASM context, which means
// things with promises and async programming.

// Note: *not* exported, because we don't want anybody outside being able to mess with the internal state.
class ElementModQImpl implements ElementModQ {
  constructor(readonly value: bigint, readonly context: GroupContext) {}

  toBigint(): bigint {
    return this.value;
  }

  toBytes(): Uint8Array {
    return bigIntToUint8Array(this.value);
  }

  get cryptoHashString(): string {
    return this.toHex();
  }

  static createHelper(
    value: bigint,
    context: GroupContext
  ): ElementModQ | undefined {
    if (value < BIG_ZERO || value >= context.Q) {
      return undefined;
    }
    return new ElementModQImpl(value, context);
  }

  static createHelperWrapping(
    value: bigint,
    minimum: number,
    context: GroupContext
  ): ElementModQ {
    let result: bigint;

    if (minimum === 0) {
      result = value % context.Q;
    } else {
      const minBig = BigInt(minimum);
      result = (value % (context.Q - minBig)) + minBig;
    }

    return new ElementModQImpl(result, context);
  }

  equals(other: ElementModQ): boolean {
    return other instanceof ElementModQImpl && this.value === other.value;
  }

  toString(): string {
    return `ElementModQ(${this.toHex()})`;
  }

  toUInt256(): UInt256 {
    return UInt256.createFrom(this.value);
  }

  greaterThan(other: ElementModQ): boolean {
    return this.value > other.toBigint();
  }

  greaterThanOrEqual(other: ElementModQ): boolean {
    return this.value >= other.toBigint();
  }

  lessThan(other: ElementModQ): boolean {
    return this.value < other.toBigint();
  }

  lessThanOrEqual(other: ElementModQ): boolean {
    return this.value <= other.toBigint();
  }

  isInBounds(): boolean {
    return this.value >= BIG_ZERO && this.value < this.context.Q;
  }

  isInBoundsNoZero(): boolean {
    return this.value > BIG_ZERO && this.value < this.context.Q;
  }

  isZero(): boolean {
    return this.value === BIG_ZERO;
  }

  toHex(): string {
    const hex = this.value.toString(16).toUpperCase();
    return hex.length % 2 === 0 ? hex : '0' + hex;
  }
}

// Note: *not* exported, because we don't want anybody outside being able to mess with the internal state.
class ElementModPImpl implements ElementModP {
  constructor(readonly value: bigint, readonly context: GroupContext) {}

  toBigint(): bigint {
    return this.value;
  }

  toBytes(): Uint8Array {
    return bigIntToUint8Array(this.value);
  }

  get cryptoHashString(): string {
    return this.toHex();
  }

  static createHelper(
    value: bigint,
    context: GroupContext
  ): ElementModP | undefined {
    if (value < BIG_ZERO || value >= context.P) {
      return undefined;
    }
    return new ElementModPImpl(value, context);
  }

  equals(other: ElementModP): boolean {
    return other instanceof ElementModPImpl && this.value === other.value;
  }

  toString(): string {
    return `ElementModP(${this.toHex()})`;
  }

  isInBounds(): boolean {
    return this.value >= BIG_ZERO && this.value < this.context.P;
  }

  isInBoundsNoZero(): boolean {
    return this.value > BIG_ZERO && this.value < this.context.P;
  }

  isValidResidue(): boolean {
    const residue = bigintModArith.modPow(
      this.value,
      this.context.Q,
      this.context.P
    );
    const result = residue === BIG_ONE && this.isInBounds();
    if (!result) {
      log.warn('GroupBigInt', `invalid residue found for ${this.value}`);
    }
    return result;
  }

  isZero(): boolean {
    return this.value === BIG_ZERO;
  }

  toHex(): string {
    const hex = this.value.toString(16).toUpperCase();
    return hex.length % 2 === 0 ? hex : '0' + hex;
  }

  greaterThan(other: ElementModP): boolean {
    return this.toBigint() > other.toBigint();
  }

  greaterThanOrEqual(other: ElementModP): boolean {
    return this.toBigint() >= other.toBigint();
  }

  lessThan(other: ElementModP): boolean {
    return this.toBigint() < other.toBigint();
  }

  lessThanOrEqual(other: ElementModP): boolean {
    return this.toBigint() <= other.toBigint();
  }

  acceleratePow(): ElementModP {
    return new AcceleratedElementModPImpl(this.value, this.context);
  }

  powP(exponent: ElementModQ | number): ElementModP {
    let e: bigint;
    switch (typeof exponent) {
      case 'number':
        // optimization for the two most common small numbers: 0 and 1
        if (exponent === 0) {
          return this.context.ONE_MOD_P; // base^0 = 1
        }
        if (exponent === 1) {
          return this; // base^1 = base
        }
        e = BigInt(exponent);
        break;
      default:
        e = exponent.toBigint();
        break;
    }

    return new ElementModPImpl(
      bigintModArith.modPow(this.toBigint(), e, this.context.P),
      this.context
    );
  }

  toMontgomeryElementModP(): MontgomeryElementModP {
    return new MontgomeryElementModPImpl(this);
  }
}

class AcceleratedElementModPImpl extends ElementModPImpl {
  readonly powRadix: PowRadix;

  constructor(readonly value: bigint, readonly context: GroupContext) {
    super(value, context);
    this.powRadix = new PowRadix(this);
  }

  acceleratePow(): ElementModP {
    // no-op because we're already accelerated
    return this;
  }

  powP(exponent: ElementModQ | number): ElementModP {
    let e: ElementModQ;
    switch (typeof exponent) {
      case 'number':
        // optimization for the two most common small numbers: 0 and 1
        if (exponent === 0) {
          return this.context.ONE_MOD_P; // base^0 = 1
        }
        if (exponent === 1) {
          return this; // base^1 = base
        }
        e = new ElementModQImpl(BigInt(exponent), this.context);
        break;
      default:
        e = exponent;
        break;
    }

    return this.powRadix.powP(e);
  }
}

class MontgomeryElementModPImpl implements MontgomeryElementModP {
  constructor(readonly value: ElementModP) {}

  multiply(other: MontgomeryElementModP): MontgomeryElementModP {
    // Total hack of an implementation for now; we're not actually doing the Montgomery
    // transformation at all; just doing all the work by delegating. The HACL implementation
    // will do the transformation for real and see insane speedups.
    return new MontgomeryElementModPImpl(
      multP(this.value, (other as MontgomeryElementModPImpl).value)
    );
  }

  toElementModP(): ElementModP {
    return this.value;
  }
}

class BigIntProductionContext implements GroupContext {
  readonly ZERO_MOD_Q: ElementModQ;
  readonly ONE_MOD_Q: ElementModQ;
  readonly TWO_MOD_Q: ElementModQ;
  readonly ZERO_MOD_P: ElementModP;
  readonly ONE_MOD_P: ElementModP;
  readonly TWO_MOD_P: ElementModP;
  readonly G_MOD_P: ElementModP;
  readonly G_SQUARED_MOD_P: ElementModP;
  readonly G_INVERSE_MOD_P: ElementModP;
  private readonly dLogger: DLogger;
  readonly electionConstants: ElectionConstants;

  constructor(
    readonly name: string,
    readonly numBits: number,
    readonly P: bigint,
    readonly Q: bigint,
    readonly G: bigint,
    readonly R: bigint
  ) {
    if (!hasUint8ArraySupport())
      throw new Error("Environment doesn't have Uint8Array support");
    if (!hasSetSupport())
      throw new Error("Environment doesn't have Set support");
    if (!hasMapSupport())
      throw new Error("Environment doesn't have Map support");
    if (!hasArrowFunctionSupport())
      throw new Error("Environment doesn't have arrow function support");
    if (!hasClassSupport())
      throw new Error("Environment doesn't have class support");
    if (!hasAsyncAwaitSupport())
      throw new Error("Environment doesn't have async-await support");
    if (!hasBigIntSupport())
      throw new Error("Environment doesn't have BigInt support");

    this.ZERO_MOD_Q = new ElementModQImpl(BIG_ZERO, this);
    this.ONE_MOD_Q = new ElementModQImpl(BIG_ONE, this);
    this.TWO_MOD_Q = new ElementModQImpl(BIG_TWO, this);
    this.ZERO_MOD_P = new ElementModPImpl(BIG_ZERO, this);
    this.ONE_MOD_P = new ElementModPImpl(BIG_ONE, this);
    this.TWO_MOD_P = new ElementModPImpl(BIG_TWO, this);
    this.G_MOD_P = new ElementModPImpl(G, this).acceleratePow();
    this.G_SQUARED_MOD_P = multP(this.G_MOD_P, this.G_MOD_P);
    this.G_INVERSE_MOD_P = multInvP(this.G_MOD_P);
    this.dLogger = new DLogger(this.G_MOD_P);
    this.electionConstants = new ElectionConstants(P, Q, R, G);
  }

  createElementModQFromHex(value: string): ElementModQ | undefined {
    return this.createElementModQ('0x' + value);
  }

  createElementModQ(value: bigint | string | number): ElementModQ | undefined {
    switch (typeof value) {
      case 'bigint':
        return ElementModQImpl.createHelper(value, this);

      case 'string':
      case 'number':
        try {
          return ElementModQImpl.createHelper(BigInt(value), this);
        } catch (Error) {
          return undefined;
        }
    }
  }

  createElementModQSafe(
    value: bigint | string | number,
    minimum?: number
  ): ElementModQ {
    if (minimum === undefined) {
      minimum = 0;
    }

    switch (typeof value) {
      case 'bigint':
        return ElementModQImpl.createHelperWrapping(value, minimum, this);

      case 'string':
      case 'number':
        try {
          return ElementModQImpl.createHelperWrapping(
            BigInt(value),
            minimum,
            this
          );
        } catch (Error) {
          return this.ZERO_MOD_Q;
        }
    }
  }

  createElementModPFromHex(value: string): ElementModP | undefined {
    return this.createElementModP('0x' + value);
  }

  createElementModP(value: bigint | string | number): ElementModP | undefined {
    switch (typeof value) {
      case 'bigint':
        return ElementModPImpl.createHelper(value, this);

      case 'string':
      case 'number':
        try {
          return ElementModPImpl.createHelper(BigInt(value), this);
        } catch (Error) {
          return undefined;
        }
    }
  }

  createElementModPSafe(value: bigint | string | number): ElementModP {
    // TODO: smarter wrapping
    return this.createElementModP(value) || this.ZERO_MOD_P;
  }

  addQ(a: ElementModQ, b: ElementModQ): ElementModQ {
    return new ElementModQImpl((a.toBigint() + b.toBigint()) % this.Q, this);
  }

  subQ(a: ElementModQ, b: ElementModQ): ElementModQ {
    // the modulo (%) operator on a negative input yields a negative output, so
    // we can't use it for subtraction.
    return this.addQ(a, this.negateQ(b));
  }

  multQ(a: ElementModQ, b: ElementModQ): ElementModQ {
    return new ElementModQImpl((a.toBigint() * b.toBigint()) % this.Q, this);
  }

  multInvQ(a: ElementModQ): ElementModQ {
    if (a.isZero()) {
      throw Error('No multiplicative inverse for zero');
    }
    return new ElementModQImpl(
      bigintModArith.modInv(a.toBigint(), this.Q),
      this
    );
  }

  negateQ(a: ElementModQ): ElementModQ {
    if (a.isZero()) {
      return a; // zero is its own additive inverse
    } else {
      return new ElementModQImpl(this.Q - a.toBigint(), this);
    }
  }

  divQ(a: ElementModQ, b: ElementModQ): ElementModQ {
    return this.multQ(a, this.multInvQ(b));
  }

  randQ(minimum?: number): ElementModQ {
    const bytes: Uint8Array = randomBytes(32);
    const bigInt = uint8ArrayToBigInt(bytes);
    return this.createElementModQSafe(bigInt, minimum);
  }

  powP(base: ElementModP, exponent: ElementModQ | number): ElementModP {
    return base.powP(exponent);
  }

  gPowP(exponent: ElementModQ | number): ElementModP {
    return this.powP(this.G_MOD_P, exponent);
  }

  multP(a: ElementModP, b: ElementModP): ElementModP {
    return new ElementModPImpl((a.toBigint() * b.toBigint()) % this.P, this);
  }

  multInvP(a: ElementModP): ElementModP {
    if (a.isZero()) {
      throw Error('No multiplicative inverse for zero');
    }
    return new ElementModPImpl(
      bigintModArith.modInv(a.toBigint(), this.P),
      this
    );
  }

  divP(a: ElementModP, b: ElementModP): ElementModP {
    return this.multP(a, this.multInvP(b));
  }

  dLogG(e: ElementModP): number | undefined {
    return this.dLogger.dLog(e);
  }
}

// internal copy, only allocated once
let bigIntContext4096Val: GroupContext | undefined = undefined;

/**
 * ElectionGuard GroupContext using bigint as the underlying engine and implementing
 * the "full-strength" 4096-bit group.
 */
export function bigIntContext4096(): GroupContext {
  if (bigIntContext4096Val === undefined) {
    bigIntContext4096Val = new BigIntProductionContext(
      'BigInt-4096 Group',
      4096,
      production4096P,
      production4096Q,
      production4096G,
      production4096R
    );
  }
  return bigIntContext4096Val;
}

let bigIntContext3072Val: GroupContext | undefined = undefined;

/**
 * ElectionGuard GroupContext using bigint as the underlying engine and implementing
 * the "pretty-much-full-strength" 3072-bit group (which can run 1.8x faster than
 * the 4096-bit group) for modular exponentiations.
 */
export function bigIntContext3072(): GroupContext {
  if (bigIntContext3072Val === undefined) {
    bigIntContext3072Val = new BigIntProductionContext(
      'BigInt-3072 Group',
      3072,
      production3072P,
      production3072Q,
      production3072G,
      production3072R
    );
  }
  return bigIntContext3072Val;
}

/**
 * Given some externally-provided ElectionConstants, either returns a suitable
 * GroupContext, or undefined to indicate an error.
 */
export function bigIntContextFromConstants(
  constants: ElectionConstants
): GroupContext | undefined {
  if (
    constants.largePrime === production4096P &&
    constants.smallPrime === production4096Q &&
    constants.cofactor === production4096R &&
    constants.generator === production4096G
  ) {
    return bigIntContext4096();
  } else if (
    constants.largePrime === production3072P &&
    constants.smallPrime === production3072Q &&
    constants.cofactor === production3072R &&
    constants.generator === production3072G
  ) {
    return bigIntContext3072();
  } else {
    return undefined;
  }
}
