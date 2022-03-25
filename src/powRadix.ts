
// Modular exponentiation performance improvements based on a design by Olivier Pereira
// https://github.com/pereira/expo-fixed-basis/blob/main/powradix.py
// referenced from Prof. Wallach's electionguard-kotlin-multiplatform project
// https://github.com/danwallach/electionguard-kotlin-multiplatform/blob/main/src/commonMain/kotlin/electionguard/core/PowRadix.kt

// DO NOT CHANGE THE CONSTANTS BELOW. For simplicity reasons, and maybe some extra performance,
// ByteArray.kBitsPerSlice is hard-coded around these specific constants.

/**
 * Different acceleration options for the `PowRadix` acceleration of modular exponentiation.
 *
 * In the most limited, embedded environment, with sometimes less than a megabyte of RAM, there's no
 * way the PowRadix acceleration structures will fit. Use the `NO_ACCELERATION` option.
 *
 * In a "low memory" situation, such as an embedded computer like a Raspberry Pi Zero (512MB of
 * RAM), the `LOW_MEMORY_USE` option will consume only 4.8MB for the generator, and presumably that
 * much again for accelerating the public key. This will still boost modular exponentiation
 * performance significantly (2x or more).
 *
 * For any modern laptop or desktop computer, the `HIGH_MEMORY_USE` will use somewhere around ten
 * times this much memory, in return for a significant performance boost (4x or more). Still, this
 * is worth it for repeated, bulk operations.
 *
 * For a batch server computation, where every little bit of performance gain is worth it, and
 * assuming we can afford over 500MB of state for the generator and that much again for the public
 * key, then the `EXTREME_MEMORY_USE` version would yield the best possible speed improvement (6x or
 * more). For the JVM, this will easily exhaust the standard heap size, so don't forget to use
 * appropriate flags to request a multi-gigabyte heap.
 */
import {ElementModP, ElementModQ, mult_p, ONE_MOD_P, pow_p} from "./group";
import {throws} from "assert";

export enum PowRadixOption {
  NO_ACCELERATION = 0,
  LOW_MEMORY_USE = 8,
  HIGH_MEMORY_USE = 12,
  EXTREME_MEMORY_USE =16
}

/**
 * The basis is to be used with future calls to the `pow` method, such that `PowRadix(basis,
 * ...).pow(e) == basis powP e, except the computation will run much faster. By specifying which
 * `PowRadixOption` to use, the table will either use more or less memory, corresponding to greater
 * acceleration.
 *
 * @see PowRadixOption
 */
export class PowRadix{
  tableLength: number;
  numColumns: number;
  table: Array<Array<ElementModP>>;
  basis: ElementModP;
  acceleration: PowRadixOption;
  constructor(basis: ElementModP, acceleration: PowRadixOption) {
    this.basis = basis;
    this.acceleration = acceleration;
    const k = acceleration;
    if (k === 0) {
      this.tableLength = 0;
      this.numColumns = 0;
      this.table = [];
    } else {
      this.tableLength = Math.ceil(256.0 / k);
      let rowBasis = basis;
      let runningBasis = rowBasis;
      this.numColumns = 1 << k;
      //row-major table
      for (let i = 0; i < this.tableLength; i++) {
        const finalRow = [];
        for (let j = 0; j < this.numColumns; j++) {
          if (j == 0) {
            finalRow[j] = ONE_MOD_P;
          } else {
            const finalColumn = runningBasis;
            runningBasis = mult_p(runningBasis, rowBasis);
            finalRow[j] = finalColumn;
          }
        }
        rowBasis = runningBasis;
        this.table[i] = finalRow;
      }
    }
  }

  pow(e: ElementModQ): ElementModP {
    if (this.acceleration == 0) {
      return pow_p(this.basis, e);
    } else {
      let slices = kBitsPerSlice(e.byteArray(), this.acceleration, this.tableLength);
      let y = ONE_MOD_P;
      for (let i = 0; i <this.tableLength; i++) {
        const eSlice = slices[i];
        const nextProd = this.table[i][eSlice]
        y = mult_p(y, nextProd);
      }
      return y;
    }
  }
}

function getOrZero(buff: ArrayBuffer, offset: number) {
  if (offset < 0 || offset >= 32) {
    throw new Error("unexpected offset: "+ offset);
  } else if (buff.byteLength === 32) {
    const view = new DataView(buff);
    return view.getUint8(offset);
  } else if (offset < (32 - buff.byteLength)) {
    return 0;
  } else {
    const view = new DataView(buff);
    return view.getUint8(offset - 32 + this.byteLength);
  }
}

function getOrZeroUShort(buff: ArrayBuffer, offset: number) {
  return getOrZero(buff, offset);
}

function kBitsPerSlice(buff: ArrayBuffer, powRadixOption: PowRadixOption, tableLength: number): Uint16Array {
  console.assert(buff.byteLength <= 32, "invalid input size"+ buff.byteLength +", not 32 bytes");

  switch (powRadixOption) {
    case PowRadixOption.LOW_MEMORY_USE: {
      console.assert(tableLength === 32, "expected tableLength to be 32, got "+ tableLength);
      const ushortArray = new Uint16Array(tableLength);
      for (let i = 0; i < tableLength; i++) {
        ushortArray[i] = getOrZeroUShort(buff, tableLength - i - 1);
      }
      return ushortArray;
    }
    default: {
      throw new Error("Acceleration k = "+ powRadixOption+" bits, which isn't supported. PowRadixOption other than LOW_MEMORY_USE not supported yet.");
    }
  }

}




