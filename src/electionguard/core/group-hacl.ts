import * as crypto from 'crypto';
import {bigIntToUint8Array, uint8ArrayToBigInt} from './utils';
import {DLogger} from './dlog';
import {
  GroupContext,
  ElementModQ,
  ElementModP,
  MontgomeryElementModP,
  BIG_ZERO,
  multP,
  multInvP,
} from './group-common';
import {
  production3072G,
  production3072P,
  production3072Q,
  production4096G,
  production4096P,
  production4096Q,
} from './constants';
import {UInt256} from './uint256';
import {PowRadix} from './powradix';

import HaclWasm from '../../../hacl-wasm/api.js';

// This file exports the symbols `haclContext4096()` and `haclContext3072(), which return
// instances of the GroupContext interface found in group-common.ts, and which implements all
// the ElementModP and ElementModQ functions that we need for ElectionGuard.

// These are async functions that will set up everything necessary to run the
// computations in the WASM subsystem.

type Hacl64_BigNum = Uint8Array;
type HaclApi = any;

const uintZero = new Uint8Array(2);
uintZero[0] = 0;
uintZero[1] = 0;

function bigIntToHacl64(hacl: HaclApi, input: bigint): Hacl64_BigNum {
  const bytes = input === BIG_ZERO ? uintZero : bigIntToUint8Array(input);
  return bytesToHacl64(hacl, bytes);
}

function hacl64ToBigInt(hacl: HaclApi, input: Hacl64_BigNum): bigint {
  return uint8ArrayToBigInt(hacl64ToBytes(hacl, input));
}

function hacl64ToBytes(hacl: HaclApi, input: Hacl64_BigNum): Uint8Array {
  return hacl.Bignum_64.bn_to_bytes_be(input);
}

function bytesToHacl64(hacl: HaclApi, input: Uint8Array): Hacl64_BigNum {
  return hacl.Bignum_64.new_bn_from_bytes_be(input);
}

class ElementModQImpl implements ElementModQ {
  constructor(
    readonly value: Hacl64_BigNum,
    readonly context: HaclProductionContext
  ) {}

  toBigint(): bigint {
    return hacl64ToBigInt(this.context.Hacl, this.value);
  }

  toBytes(): Uint8Array {
    return bigIntToUint8Array(this.toBigint());
  }

  get cryptoHashString(): string {
    return this.toHex();
  }

  static createHelper(
    value: bigint,
    context: HaclProductionContext
  ): ElementModQImpl | undefined {
    if (value < BIG_ZERO || value >= context.Q) {
      return undefined;
    }
    return new ElementModQImpl(bigIntToHacl64(context.Hacl, value), context);
  }

  static createHelperWrapping(
    value: bigint,
    minimum: number,
    context: HaclProductionContext
  ): ElementModQImpl {
    let result: bigint;

    if (minimum === 0) {
      result = value % context.Q;
    } else {
      const minBig = BigInt(minimum);
      result = (value % (context.Q - minBig)) + minBig;
    }

    return new ElementModQImpl(bigIntToHacl64(context.Hacl, result), context);
  }

  equals(other: ElementModQ): boolean {
    return (
      other instanceof ElementModQImpl &&
      this.context.Hacl.Bignum_64.eq_mask(this.value, other.value)
    );
  }

  toString(): string {
    return `ElementModQ(${this.toHex()})`;
  }

  toUInt256(): UInt256 {
    return UInt256.createFromBytesRightPad(this.toBytes());
  }

  greaterThan(other: ElementModQ): boolean {
    return !this.lessThanOrEqual(other);
  }

  greaterThanOrEqual(other: ElementModQ): boolean {
    return !this.lessThan(other);
  }

  lessThan(other: ElementModQ): boolean {
    return (
      other instanceof ElementModQImpl &&
      this.context.Hacl.Bignum_64.lt_mask(this.value, other.value)
    );
  }

  lessThanOrEqual(other: ElementModQ): boolean {
    return this.equals(other) || this.lessThan(other);
  }

  isInBounds(): boolean {
    return this.context.Hacl.Bignum_64.lt_mask(this.value, this.context.HACL_Q);
  }

  isInBoundsNoZero(): boolean {
    return this.isInBounds() && !this.isZero();
  }

  isZero(): boolean {
    return this.equals(this.context.ZERO_MOD_Q);
  }

  toHex(): string {
    return this.toBigint().toString(16).toUpperCase();
  }
}

// Note: *not* exported, because we don't want anybody outside being able to mess with the internal state.
class ElementModPImpl implements ElementModP {
  constructor(
    readonly value: Hacl64_BigNum,
    readonly context: HaclProductionContext
  ) {}

  toBigint(): bigint {
    return hacl64ToBigInt(this.context.Hacl, this.value);
  }

  toBytes(): Uint8Array {
    return bigIntToUint8Array(this.toBigint());
  }

  get cryptoHashString(): string {
    return this.toHex();
  }

  static createHelper(
    value: bigint,
    context: HaclProductionContext
  ): ElementModPImpl | undefined {
    if (value < BIG_ZERO || value >= context.P) {
      return undefined;
    }
    return new ElementModPImpl(bigIntToHacl64(context.Hacl, value), context);
  }

  greaterThan(other: ElementModP): boolean {
    return !this.lessThanOrEqual(other);
  }

  greaterThanOrEqual(other: ElementModP): boolean {
    return !this.lessThan(other);
  }

  lessThan(other: ElementModP): boolean {
    return (
      other instanceof ElementModQImpl &&
      this.context.Hacl.Bignum_64.lt_mask(this.value, other.value)
    );
  }

  lessThanOrEqual(other: ElementModP): boolean {
    return this.equals(other) || this.lessThan(other);
  }

  isInBounds(): boolean {
    return this.context.Hacl.Bignum_64.lt_mask(this.value, this.context.HACL_P);
  }

  isInBoundsNoZero(): boolean {
    return this.isInBounds() && !this.isZero();
  }

  isZero(): boolean {
    return this.equals(this.context.ZERO_MOD_P);
  }

  equals(other: ElementModP): boolean {
    return (
      other instanceof ElementModPImpl &&
      this.context.Hacl.Bignum_64.eq_mask(this.value, other.value)
    );
  }

  toString(): string {
    return `ElementModP(${this.toHex()})`;
  }

  isValidResidue(): boolean {
    const residue = this.context.Hacl.Bignum_64.mod_exp_vartime_precomp(
      this.context.MONT_CTX_P,
      this.value,
      this.context.HACL_Q
    );

    return this.isInBounds() && residue.equals(this.context.ONE_MOD_P);
  }

  toHex(): string {
    return this.toBigint().toString(16).toUpperCase();
  }

  acceleratePow(): ElementModP {
    return this;
    // return new AcceleratedElementModPImpl(this.value, this.context);
  }

  powP(exponent: ElementModQ | number): ElementModP {
    let e: ElementModQImpl;
    switch (typeof exponent) {
      case 'number': {
        // optimization for the two most common small numbers: 0 and 1
        if (exponent === 0) {
          return this.context.ONE_MOD_P; // base^0 = 1
        }
        if (exponent === 1) {
          return this; // base^1 = base
        }
        const maybeE = ElementModQImpl.createHelper(
          BigInt(exponent),
          this.context
        );

        if (maybeE === undefined) {
          throw new Error(`unexpected value for exponent: ${exponent}`);
        } else {
          e = maybeE;
        }
        break;
      }
      default:
        if (exponent instanceof ElementModQImpl) {
          e = exponent;
        } else {
          throw new Error('unexpected type for exponent');
        }
        break;
    }

    const result = this.context.Hacl.Bignum_64.mod_exp_vartime_precomp(
      this.context.MONT_CTX_P,
      this.value,
      e.value
    );

    return new ElementModPImpl(result, this.context);
  }

  toMontgomeryElementModP(): MontgomeryElementModP {
    return new MontgomeryElementModPImpl(this);
  }
}

class AcceleratedElementModPImpl extends ElementModPImpl {
  readonly powRadix: PowRadix;

  constructor(
    readonly value: Hacl64_BigNum,
    readonly context: HaclProductionContext
  ) {
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
      case 'number': {
        // optimization for the two most common small numbers: 0 and 1
        if (exponent === 0) {
          return this.context.ONE_MOD_P; // base^0 = 1
        }
        if (exponent === 1) {
          return this; // base^1 = base
        }
        const maybeE = ElementModQImpl.createHelper(
          BigInt(exponent),
          this.context
        );
        if (maybeE === undefined) {
          throw new Error(
            `unexpected failure to create exponent from ${exponent}`
          );
        } else {
          e = maybeE;
        }
        break;
      }
      default:
        e = exponent;
        break;
    }

    return this.powRadix.powP(e);
  }
}

class MontgomeryElementModPImpl implements MontgomeryElementModP {
  // TODO: use the Montgomery transformation built into HACL-WASM for speed!
  constructor(readonly value: ElementModP) {}

  multiply(other: MontgomeryElementModP): MontgomeryElementModP {
    return new MontgomeryElementModPImpl(
      multP(this.value, (other as MontgomeryElementModPImpl).value)
    );
  }

  toElementModP(): ElementModP {
    return this.value;
  }
}

type Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64 = any;

class HaclProductionContext implements GroupContext {
  readonly ZERO_MOD_Q: ElementModQ;
  readonly ONE_MOD_Q: ElementModQ;
  readonly TWO_MOD_Q: ElementModQ;
  readonly Q_MINUS_ONE_MOD_Q: ElementModQ;
  readonly ZERO_MOD_P: ElementModP;
  readonly ONE_MOD_P: ElementModP;
  readonly TWO_MOD_P: ElementModP;
  readonly G_MOD_P: ElementModP;
  readonly G_SQUARED_MOD_P: ElementModP;
  readonly G_INVERSE_MOD_P: ElementModP;
  readonly HACL_ZERO: Hacl64_BigNum;
  readonly HACL_ONE: Hacl64_BigNum;
  readonly HACL_TWO: Hacl64_BigNum;
  readonly HACL_P: Hacl64_BigNum;
  readonly HACL_Q: Hacl64_BigNum;
  readonly HACL_G: Hacl64_BigNum;
  readonly MONT_CTX_P: Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64;
  readonly MONT_CTX_Q: Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64;
  readonly MONT_FIELD_CTX: Hacl_Bignum_MontArithmetic_bn_mont_ctx_u64;
  private readonly dLogger: DLogger;

  constructor(
    readonly name: string,
    readonly numBits: number,
    readonly P: bigint,
    readonly Q: bigint,
    readonly G: bigint,
    readonly Hacl: HaclApi // Hacl API object
  ) {
    console.log(`Initializing context for ${name} (${numBits} bits)`);
    this.HACL_ZERO = bigIntToHacl64(Hacl, BigInt(0));
    this.HACL_ONE = bigIntToHacl64(Hacl, BigInt(1));
    this.HACL_TWO = bigIntToHacl64(Hacl, BigInt(2));
    this.HACL_P = bigIntToHacl64(Hacl, P);
    this.HACL_Q = bigIntToHacl64(Hacl, Q);
    this.HACL_G = bigIntToHacl64(Hacl, G);

    this.MONT_CTX_P = Hacl.Bignum_64.mont_ctx_init(this.HACL_P);
    this.MONT_CTX_Q = Hacl.Bignum_64.mont_ctx_init(this.HACL_Q);
    this.MONT_FIELD_CTX = Hacl.Bignum_Montgomery_64.field_init(this.HACL_P);

    this.ZERO_MOD_Q = new ElementModQImpl(this.HACL_ZERO, this);
    this.ONE_MOD_Q = new ElementModQImpl(this.HACL_ONE, this);
    this.TWO_MOD_Q = new ElementModQImpl(this.HACL_TWO, this);
    this.ZERO_MOD_P = new ElementModPImpl(this.HACL_ZERO, this);
    this.ONE_MOD_P = new ElementModPImpl(this.HACL_ONE, this);
    this.TWO_MOD_P = new ElementModPImpl(this.HACL_TWO, this);
    this.G_MOD_P = new ElementModPImpl(this.HACL_G, this); //.acceleratePow();

    console.log('Initialization: about to try multiplication');
    this.G_SQUARED_MOD_P = multP(this.G_MOD_P, this.G_MOD_P);
    this.G_INVERSE_MOD_P = multInvP(this.G_MOD_P);

    this.Q_MINUS_ONE_MOD_Q = new ElementModQImpl(
      bigIntToHacl64(Hacl, Q - BigInt(1)),
      this
    );

    this.dLogger = new DLogger(this.G_MOD_P);
    console.log('Initialization complete');
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
    const result = this.Hacl.Bignum_64.add_mod(
      this.HACL_Q,
      (a as ElementModQImpl).value,
      (b as ElementModQImpl).value
    );
    return new ElementModQImpl(result, this);
  }

  subQ(a: ElementModQ, b: ElementModQ): ElementModQ {
    const result = this.Hacl.Bignum_64.sub_mod(
      this.HACL_Q,
      (a as ElementModQImpl).value,
      (b as ElementModQImpl).value
    );
    return new ElementModQImpl(result, this);
  }

  multQ(a: ElementModQ, b: ElementModQ): ElementModQ {
    const product = this.Hacl.Bignum_64.mul(
      (a as ElementModQImpl).value,
      (b as ElementModQImpl).value
    );
    const result = this.Hacl.Bignum_64.mod(this.HACL_Q, product);
    return new ElementModQImpl(result, this);
  }

  multInvQ(a: ElementModQ): ElementModQ {
    if (a.isZero()) {
      throw Error('No multiplicative inverse for zero');
    }

    const result = this.Hacl.Bignum_64.mod_inv_prime_vartime_precomp(
      this.MONT_CTX_Q,
      (a as ElementModQImpl).value
    );
    return new ElementModQImpl(result, this);
  }

  negateQ(a: ElementModQ): ElementModQ {
    if (a.isZero()) {
      return a; // zero is its own additive inverse
    } else {
      const result = this.Hacl.Bignum_64.sub(
        this.HACL_Q,
        (a as ElementModQImpl).value
      );
      return new ElementModQImpl(result, this);
    }
  }

  divQ(a: ElementModQ, b: ElementModQ): ElementModQ {
    return this.multQ(a, this.multInvQ(b));
  }

  randQ(minimum?: number): ElementModQ {
    const bytes: Uint8Array = crypto.randomBytes(32);
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
    const product = this.Hacl.Bignum_64.mul(
      (a as ElementModPImpl).value,
      (b as ElementModPImpl).value
    );
    const result = this.Hacl.Bignum_64.mod_precomp(this.MONT_CTX_P, product);
    return new ElementModPImpl(result, this);
  }

  multInvP(a: ElementModP): ElementModP {
    if (a.isZero()) {
      throw Error('No multiplicative inverse for zero');
    }

    // optimization: taking advantage of the subgroup structure,
    // this turns out to be much, much faster than computing
    // the multiplicative inverse.
    return a.powP(this.Q_MINUS_ONE_MOD_Q);
  }

  divP(a: ElementModP, b: ElementModP): ElementModP {
    return this.multP(a, this.multInvP(b));
  }

  dLogG(e: ElementModP): number | undefined {
    return this.dLogger.dLog(e);
  }
}

// internal copy, only allocated once
let haclContext4096Val: GroupContext | undefined = undefined;

const haclModules = [
  'WasmSupport',
  'FStar',
  'Hacl_Bignum',
  'Hacl_GenericField64',
  'Hacl_Bignum64',
];

/**
 * ElectionGuard GroupContext using hacl-wasm as the underlying engine and implementing
 * the "full-strength" 4096-bit group.
 */
export function haclContext4096(): Promise<GroupContext> {
  if (haclContext4096Val === undefined) {
    return HaclWasm.getInitializedHaclModule(haclModules).then(HaclApi => {
      haclContext4096Val = new HaclProductionContext(
        'Hacl-4096 Group',
        4096,
        production4096P,
        production4096Q,
        production4096G,
        HaclApi
      );
      return haclContext4096Val;
    });
  } else {
    return Promise.resolve(haclContext4096Val);
  }
}

let haclContext3072Val: GroupContext | undefined = undefined;

/**
 * ElectionGuard GroupContext using hacl-wasm as the underlying engine and implementing
 * the "pretty-much-full-strength" 3072-bit group (which can run 1.8x faster than
 * the 4096-bit group) for modular exponentiations.
 */
export function haclContext3072(): Promise<GroupContext> {
  if (haclContext3072Val === undefined) {
    return HaclWasm.getInitializedHaclModule(haclModules).then(HaclApi => {
      haclContext3072Val = new HaclProductionContext(
        'Hacl-3072 Group',
        3072,
        production3072P,
        production3072Q,
        production3072G,
        HaclApi
      );
      return haclContext3072Val;
    });
  } else {
    return Promise.resolve(haclContext3072Val);
  }
}
