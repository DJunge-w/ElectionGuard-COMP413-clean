import {
    P,
    Q,
    ElementModP,
    ElementModQ,
    a_minus_b_q,
    mult_inv_p,
    ONE_MOD_P,
    mult_p,
    ZERO_MOD_P,
    G,
    ONE_MOD_Q,
    g_pow_p,
    ZERO_MOD_Q,
    R,
    int_to_p,
    int_to_q,
    add_q,
    div_q,
    div_p,
    a_plus_bc_q,
    int_to_p_unchecked,
    int_to_q_unchecked,
    convertBase,
    groupDigits,
} from './group';

import {
    flatmap_optional,
    get_or_else_optional,
    match_optional,
    get_optional,
} from './utils';

import {
    elements_mod_q,
    elements_mod_p,
    elements_mod_p_no_zero,
    elements_mod_q_no_zero,
    // getRandomIntExclusive
} from './groupUtils';

describe("TestBigIntToHex", () => {
    const randomQ: ElementModQ = elements_mod_q();
    const randomP: ElementModP = elements_mod_p();
    expect(BigInt("0x" + randomQ.to_hex())).toEqual(randomQ.elem);
    expect(BigInt("0x" + randomP.to_hex())).toEqual(randomP.elem);
});

describe("TestBinaryBigIntConversion", () => {
    const largeNumber:string =
        '1101001101011010000101001111101001011101' +
        '1111000010010111000111110011111011111000' +
        '0011000001100000110000011001110101001110' +
        '1010111010001000101101010111001111000001' +
        '1000001100000110000011001001100000110000' +
        '0110000011000001100001110000111000001100' +
        '0001100000110000011000001100001010110001' +
        '1001110101101001100110100100000110000011' +
        '0000011000001100010011010111101100100010' +
        '1101000110101101010001100100111000111001' +
        '0100111011011111010000110001110010101010' +
        '0011110100100001011000010000011000010110' +
        '0001101111100001111000111011111001111111' +
        '1000100011110110101000101100000110000011' +
        '0000011000001100000110100111010101101011' +
        '0100111110100101001011110101100001110110' +
        '0110010011001001111101';

    test('testConvertBaseFrom2To10', () => {

      //convert largeNumber from base 2 to base 10
      const largeIntDecimal = convertBase(largeNumber, 2, 10);
      const expectedLargeIntStr = '15 798 770 299 367 407 029 725 345 423 297 491 683 306 908 462 684 165 669 735 033 278 996 876 231 474 309 788 453 071 122 111 686 268 816 862 247 538 905 966 252 886 886 438 931 450 432 740 640 141 331 094 589 505 960 171 298 398 097 197 475 262 433 234 991 526 525';
      expect(groupDigits(largeIntDecimal)).toBe(expectedLargeIntStr);
    });

    test('testConvertBaseFrom10To2', () => {
        //convert largeNumber from base 2 to base 10
        const largeIntDecimal = convertBase(largeNumber, 2, 10);
        //converting back to base 2:
        const restoredOriginal = convertBase(largeIntDecimal, 10, 2);
         //check that it matches the original:
        expect(restoredOriginal).toBe(largeNumber);
    });
});

describe("TestEquality", () => {
    test('testPsNotEqualToQs', () => {
        const q = elements_mod_q();
        const q2 = elements_mod_q();
        const p: ElementModP = int_to_p_unchecked(q.to_int());
        const p2: ElementModP = int_to_p_unchecked(q2.to_int());

        // same value should imply they're equal
        expect(q.equals(p)).toBe(true);
        expect(q2.equals(p2)).toBe(true);

        if (q.to_int() !== q2.to_int()) {
            // these are genuinely different numbers
            expect(q.notEqual(q2)).toBe(true);
            expect(p.notEqual(p2)).toBe(true);
            expect(q.notEqual(p2)).toBe(true);
            expect(p.notEqual(q2)).toBe(true);
        }
        // of course, we're going to make sure that a number is equal to itself
        expect(q.equals(q)).toBe(true);
        expect(p.equals(p)).toBe(true);
    })
});

describe("TestModularArithmetic", () => {
    test('testAddQ', () => {
        const q: ElementModQ = elements_mod_q();
        const asInt: ElementModQ = add_q(q, 1n);
        const asElem: ElementModQ = add_q(q, new ElementModQ(BigInt(1)));
        expect(asInt.equals(asElem)).toBe(true);
    });

    test('testAPlusBCQ', () => {
        const q: ElementModQ = elements_mod_q();
        const asInt: ElementModQ = a_plus_bc_q(q, 1n, 1n);
        const asElem: ElementModQ = a_plus_bc_q(q, new ElementModQ(BigInt(1)), new ElementModQ(BigInt(1)));
        expect(asInt.equals(asElem)).toBe(true);
    });

    test('testAMinusBQ', () => {
        const q: ElementModQ = elements_mod_q();
        const asInt: ElementModQ = a_minus_b_q(q, 1n);
        const asElem: ElementModQ = a_minus_b_q(q, new ElementModQ(BigInt(1)));
        expect(asInt.equals(asElem)).toBe(true);
    });

    test('testDivQ', () => {
        const q: ElementModQ = elements_mod_q();
        const asInt: ElementModQ = div_q(q, 1n);
        const asElem: ElementModQ = div_q(q, new ElementModQ(BigInt(1)));
        expect(asInt.equals(asElem)).toBe(true);
        expect(asInt.equals(q)).toBe(true);
        expect(asElem.equals(q)).toBe(true);
    });

    test('testDivP', () => {
        const p: ElementModP = elements_mod_p();
        const asInt: ElementModP = div_p(p, 1n);
        const asElem: ElementModP = div_p(p, new ElementModP(BigInt(1)));
        expect(asInt.equals(asElem)).toBe(true);
        expect(asInt.equals(p)).toBe(true);
        expect(asElem.equals(p)).toBe(true);
    });

    test('testNoMultInvOfZero', () => {
        // TODO: may need to know which exception to throw
        expect(() => mult_inv_p(ZERO_MOD_P)).toThrow(Error);
    });

    // TODO: the current powmod function is not efficient enough for large number like P
    test('testMultInverses', () => {
        const elem: ElementModP = elements_mod_p_no_zero();
        const inv: ElementModP = mult_inv_p(elem);
        expect(mult_p(elem, inv).equals(ONE_MOD_P)).toBe(true);
    });

    test('testMultIdentity', () => {
        const elem: ElementModP = elements_mod_p();
        expect(elem.equals(mult_p(elem))).toBe(true);
    });

    test('testMultNoArgs', () => {
        expect(ONE_MOD_P.equals(mult_p())).toBe(true);
    });

    test('testAddNoArgs', () => {
        expect(ZERO_MOD_Q.equals(add_q())).toBe(true);
    });

    test('testPropertiesForConstants', () => {
        expect(G as bigint !== 1n).toBe(true);
        expect((R * Q) % P).toEqual(P - 1n);
        expect(Q).toBeLessThan(P);
        expect(G).toBeLessThan(P);
        expect(R).toBeLessThan(P);
    });

    test('testSimplePowers', () => {
        let gp: ElementModP | null = int_to_p(G);
        gp = get_optional(gp);
        expect(gp.equals(g_pow_p(ONE_MOD_Q))).toBe(true);
        expect(ONE_MOD_P.equals(g_pow_p(ZERO_MOD_Q)));

    });

    test('testInBoundsQ', () => {
        const q: ElementModQ = elements_mod_q();
        expect(q.is_in_bounds()).toBe(true);
        const tooBig: bigint = q.to_int() + Q;
        const tooSmall: bigint = q.to_int() - Q;
        expect(int_to_q_unchecked(tooBig).is_in_bounds()).toBe(false);
        expect(int_to_q_unchecked(tooSmall).is_in_bounds()).toBe(false);
        expect(int_to_q(tooBig)).toEqual(null);
        expect(int_to_q(tooSmall)).toEqual(null);
    });

    test('testInBoundsP', () => {
        const p: ElementModP = elements_mod_p();
        expect(p.is_in_bounds()).toBe(true);
        const tooBig: bigint = p.to_int() + P;
        const tooSmall: bigint = p.to_int() - P;
        expect(int_to_p_unchecked(tooBig).is_in_bounds()).toBe(false);
        expect(int_to_p_unchecked(tooSmall).is_in_bounds()).toBe(false);
        expect(int_to_p(tooBig)).toEqual(null);
        expect(int_to_p(tooSmall)).toEqual(null);
    });

    test('testInBoundsQNoZero', () => {
        const q: ElementModQ = elements_mod_q_no_zero();
        expect(q.is_in_bounds_no_zero()).toBe(true);
        expect(ZERO_MOD_Q.is_in_bounds_no_zero()).toBe(false);
        expect(int_to_q_unchecked(q.to_int() + Q).is_in_bounds_no_zero()).toBe(false);
        expect(int_to_q_unchecked(q.to_int() - Q).is_in_bounds_no_zero()).toBe(false);
    });

    test('testInBoundsPNoZero', () => {
        const p: ElementModP = elements_mod_p_no_zero();
        expect(p.is_in_bounds_no_zero()).toBe(true);
        expect(ZERO_MOD_P.is_in_bounds_no_zero()).toBe(false);
        expect(int_to_p_unchecked(p.to_int() + P).is_in_bounds_no_zero()).toBe(false);
        expect(int_to_p_unchecked(p.to_int() - P).is_in_bounds_no_zero()).toBe(false);
    });

    test('testLargeValuesRejectedByInToQ', () => {
        const q: ElementModQ = elements_mod_q();
        const oversize: bigint = q.to_int() + Q;
        expect(int_to_q(oversize)).toEqual(null);
    });
});

describe("TestOptionalFunctions", () => {
    test('testUnwrap', () => {
        const good: number | null = 3;
        const bad: number | null = null;
        expect(get_optional(good)).toEqual(3);
        expect(() => get_optional(bad)).toThrow(Error);
    });

    test('testMatch', () => {
        const good: number | null = 3;
        const bad: number | null = null;
        expect(match_optional(good, () => 1, (x) => x + 2)).toEqual(5);
        expect(match_optional(bad, () => 1, (x) => {
          if (x == null || x == undefined) {
            throw Error("match called on null or undefined.");
          }
          return x + 2;
        })).toEqual(1);
    });

    test('testGetOrElse', () => {
        const good: number | null = 3;
        const bad: number | null = null;
        expect(get_or_else_optional(good, 5)).toEqual(3);
        expect(get_or_else_optional(bad, 5)).toEqual(5);
    });

    test('testFlatMap', () => {
        const good: number | null = 3;
        const bad: number | null = null;
        expect(get_optional(flatmap_optional(good, (x) => x + 2))).toEqual(5);
        expect(flatmap_optional(bad, (x) => {
          if (x == null || x == undefined) {
            throw Error("flatmap called on null or undefined")
          }
          return x + 2;
        })).toBeUndefined();
    });
});

// TODO: We probably don't need testPickling
// class TestPickling(unittest.TestCase):
//     @given(elements_mod_p())
//     def test_pickle_p(self, p: ElementModP):
//         self.assertEqual(p, pickle.loads(pickle.dumps(p)))

//     @given(elements_mod_q())
//     def test_pickle_q(self, q: ElementModQ):
//         self.assertEqual(q, pickle.loads(pickle.dumps(q)))
