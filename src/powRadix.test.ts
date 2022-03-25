import {kBitsPerSlice, PowRadix, PowRadixOption} from "./powRadix";
import {ElementModQ, G_MOD_P, G_SQUARED_MOD_P, ONE_MOD_P, ONE_MOD_Q, pow_p, TWO_MOD_Q, ZERO_MOD_Q} from "./group";

// function testExponentiationGeneric(option: PowRadixOption) {
//   // We're comparing the accelerated powRadix version (with the specified PowRadixOption)
//   // with the unaccelerated version.
//
//
// }
describe("TestPowRadix", () => {
  test("bitSlicingSimplePattern", ()=>{
    const testBtyesView = new Uint8Array(32);
    testBtyesView.fill(parseInt("8F", 16));
    const testBytes = testBtyesView.buffer;
    const expectedSliceSmall = new Uint16Array(32);
    expectedSliceSmall.fill(parseInt("8F",16));

    expect(expectedSliceSmall).toStrictEqual(kBitsPerSlice(testBytes, PowRadixOption.LOW_MEMORY_USE, 32));
  });

  test("bitSlicingIncreasing", () => {
    // most significant bits are at testBytes[0], which will start off with value
    // one and then increase on our way through the array
    const testBtyesView = new Uint8Array(32);
    testBtyesView.map((element, index) => {
      void element;
      return index + 1;
    });
    const testBytes = testBtyesView.buffer;
    const expectedSliceSmall = new Uint16Array(32);
    expectedSliceSmall.map((element, index) => {
      void element;
      return 32 - index;
    });

    expect(expectedSliceSmall).toStrictEqual(kBitsPerSlice(testBytes, PowRadixOption.LOW_MEMORY_USE, 32));

  });

  test("bitSlicingBasics", () => {
    const option = PowRadixOption.LOW_MEMORY_USE;
    const powRadix = new PowRadix(G_MOD_P, option);

    const bytes = new ElementModQ(258).byteArray();
    //validate it's big-endian
    const view = new DataView(bytes);
    expect(1).toBe(view.getUint8(bytes.byteLength - 2));
    expect(2).toBe(view.getUint8(bytes.byteLength - 1));

    const slices = kBitsPerSlice(bytes, option, powRadix.tableLength);
    //validate it's little-endian
    expect(2).toBe(slices[0]);
    expect(1).toBe(slices[1]);
    expect(0).toBe(slices[2]);
  });

  test("testExponentiationLowMem", () => {
    const powRadix = new PowRadix(G_MOD_P, PowRadixOption.LOW_MEMORY_USE);
    expect(ONE_MOD_P).toStrictEqual(powRadix.pow(ZERO_MOD_Q));
    expect(G_MOD_P).toStrictEqual(powRadix.pow(ONE_MOD_Q));
    expect(G_SQUARED_MOD_P).toStrictEqual(powRadix.pow(TWO_MOD_Q));

    expect(pow_p(G_MOD_P, new ElementModQ(10))).toStrictEqual(powRadix.pow(new ElementModQ(10)))
    expect(pow_p(G_MOD_P, new ElementModQ(100))).toStrictEqual(powRadix.pow(new ElementModQ(100)))
    expect(pow_p(G_MOD_P, new ElementModQ(1000))).toStrictEqual(powRadix.pow(new ElementModQ(1000)))
  });
});
