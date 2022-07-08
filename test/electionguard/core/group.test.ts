import * as fc from 'fast-check';
import {
  elementModQ,
  elementModP,
  validElementModP,
  fcFastConfig,
} from './generators';
import {
  addQ,
  compatibleContextOrFail,
  divP,
  GroupContext,
  multInvP,
  multInvQ,
  multP,
  multQ,
  negateQ,
  powP,
  subQ,
} from '../../../src/electionguard/core/group-common';
import {
  bigIntContext4096,
  bigIntContext3072,
} from '../../../src/electionguard/core/group-bigint';

/**
 * General-purpose tester for anything that implements the GroupContext interface.
 */
export function testGroup(context: GroupContext): void {
  describe(`${context.name}: super basics`, () => {
    test('addition basics', () => {
      const three = context.createElementModQ(3) || fail(); // requires not undefined
      const four = context.createElementModQ(4) || fail();
      const seven = context.createElementModQ(7) || fail();
      expect(context.addQ(three, four)).toEqual(seven);
    });

    test('multiplication basics', () => {
      const three = context.createElementModQ(3) || fail();
      const four = context.createElementModQ(4) || fail();
      const twelve = context.createElementModQ(12) || fail();
      expect(context.multQ(three, four)).toEqual(twelve);
    });

    test('constants are in bounds', () => {
      expect(context.G < context.P).toBe(true);
      expect(context.Q < context.P).toBe(true);
    });

    test('super basic equality testing', () => {
      expect(context.createElementModQ(0)).toEqual(context.ZERO_MOD_Q);
      expect(context.createElementModQ(0)?.isZero()).toBe(true);
      expect(context.ZERO_MOD_Q).toEqual(context.createElementModQ(0));
      expect(context.ZERO_MOD_Q).toEqual(context.ZERO_MOD_Q);
      expect(context.ZERO_MOD_P).toEqual(context.ZERO_MOD_P);
    });
  });

  describe(`${context.name}: properties on ElementModQ`, () => {
    test('addition laws', () => {
      fc.assert(
        fc.property(
          elementModQ(context),
          elementModQ(context),
          elementModQ(context),
          (a, b, c) => {
            expect(addQ(a, context.ZERO_MOD_Q)).toEqual(a); // identity
            expect(negateQ(a).isInBounds()).toBe(true); // closure
            expect(subQ(a, b).isInBounds()).toBe(true); // closure
            expect(addQ(a, negateQ(a))).toEqual(context.ZERO_MOD_Q); // inverse
            const aPlusB = addQ(a, b);
            expect(aPlusB.isInBounds()).toBe(true); // closure
            expect(aPlusB).toEqual(addQ(b, a)); // commutativity
            expect(addQ(a, addQ(b, c))).toEqual(addQ(addQ(a, b), c)); // associativity
          }
        )
      );
    });

    test('multiplication laws', () => {
      fc.assert(
        fc.property(
          elementModQ(context),
          elementModQ(context),
          elementModQ(context),
          (a, b, c) => {
            expect(multQ(a, context.ONE_MOD_Q)).toEqual(a); // identity
            if (!a.isZero()) {
              expect(multQ(multInvQ(a), a)).toEqual(context.ONE_MOD_Q); // inverse
            }
            const aTimesB = multQ(a, b);
            expect(aTimesB.isInBounds()).toBe(true); // closure
            expect(aTimesB).toEqual(multQ(b, a)); // commutativity
            expect(multQ(a, multQ(b, c))).toEqual(multQ(multQ(a, b), c)); // associativity
            expect(multQ(a, addQ(b, c))).toEqual(
              addQ(multQ(a, b), multQ(a, c))
            ); // distribution
          }
        )
      );
    });

    test('serialization', () => {
      fc.assert(
        fc.property(elementModQ(context), a => {
          expect(context.createElementModQFromHex(a.toHex())).toEqual(a);
        })
      );
    });

    test('randomness', () => {
      fc.assert(
        fc.property(fc.nat(100), min => {
          const r1 = context.randQ(min);
          const r2 = context.randQ(min);
          const minQ = context.createElementModQ(min) || fail();
          expect(r1).not.toEqual(r2); // the probability of equality should be basically zero
          expect(r1.greaterThanOrEqual(minQ)).toBe(true);
          expect(r2.greaterThanOrEqual(minQ)).toBe(true);
        })
      );
    });
  });

  describe(`${context.name}: properties on ElementModP`, () => {
    test('valid residues', () => {
      fc.assert(
        fc.property(validElementModP(context), x => {
          // if this isn't true, the generator is broken and we have bigger problems
          const inBounds = x.isInBoundsNoZero();
          const isValidResidue = x.isValidResidue();
          expect(x.toBigint() < context.P).toBe(true);
          expect(inBounds).toBe(true);
          expect(isValidResidue).toBe(true);
        })
      );
    });

    test('multiplication laws', () => {
      fc.assert(
        fc.property(
          validElementModP(context),
          validElementModP(context),
          validElementModP(context),
          (a, b, c) => {
            expect(multP(a, context.ONE_MOD_P)).toEqual(a); // identity
            expect(multP(multInvP(a), a)).toEqual(context.ONE_MOD_P); // inverse
            const aTimesB = multP(a, b);
            expect(aTimesB.isInBoundsNoZero()).toBe(true); // closure
            expect(aTimesB.isValidResidue()).toBe(true); // subgroup closure
            expect(divP(aTimesB, b)).toEqual(a); // inverse
            expect(aTimesB).toEqual(multP(b, a)); // commutativity
            expect(multP(a, multP(b, c))).toEqual(multP(aTimesB, c)); // associativity
          }
        )
      );
    });

    test('exponentiation laws', () => {
      fc.assert(
        fc.property(
          validElementModP(context),
          elementModQ(context),
          elementModQ(context),
          (b, e1, e2) => {
            const be1 = powP(b, e1);
            const be2 = powP(b, e2);
            const be12 = powP(b, addQ(e1, e2));
            const success = be12.equals(multP(be1, be2));
            expect(success).toBe(true); // exponents add

            const success2 = be1.isValidResidue();
            expect(success2).toBe(true); // subgroup closure

            const success3 = divP(be12, be2).equals(be1); // division inverse of multiplication
            expect(success3).toBe(true);

            const success4 = multP(be12, powP(b, negateQ(e2))).equals(be1);
            expect(success4).toBe(true);
            // negative powers work as an alternative to division
          }
        )
      );
    });

    test('super-basic generator exponentiation', () => {
      const g = context.createElementModP(context.G) || fail(); // unaccelerated generator
      expect(powP(g, 0).toBigint()).toEqual(BigInt(1));
      expect(powP(g, 1).toBigint()).toEqual(context.G);
      expect(powP(g, 2).toBigint()).toEqual(
        (context.G * context.G) % context.P
      );

      expect(context.gPowP(0)).toEqual(context.ONE_MOD_P);
      expect(context.gPowP(1)).toEqual(context.G_MOD_P);
      expect(context.gPowP(2)).toEqual(context.G_SQUARED_MOD_P);
    });

    test('generator exponentiation acceleration', () => {
      fc.assert(
        fc.property(elementModQ(context), e1 => {
          const g = context.createElementModP(context.G) || fail(); // unaccelerated generator
          const r1 = context.gPowP(e1);
          const r2 = powP(g, e1);
          expect(r1).toEqual(r2);
        }),
        fcFastConfig
      );
    });

    test('public-key exponentiation acceleration', () => {
      fc.assert(
        fc.property(elementModQ(context), elementModQ(context), (a, e) => {
          const pkNormal = context.gPowP(a);
          const pkAccel = pkNormal.acceleratePow();

          const r1 = powP(pkNormal, e);
          const r2 = powP(pkAccel, e);
          expect(r1).toEqual(r2);
        }),
        fcFastConfig
      );
    });

    test('exponentiation laws (generator)', () => {
      fc.assert(
        fc.property(elementModQ(context), elementModQ(context), (e1, e2) => {
          const r1 = context.gPowP(addQ(e1, e2));
          const ge1 = context.gPowP(e1);
          const ge2 = context.gPowP(e2);
          const r2 = multP(ge1, ge2);
          const success1 = r1.equals(r2);
          expect(success1).toBe(true); // exponents add

          const success2 = ge1.isValidResidue();
          expect(success2).toBe(true); // subgroup closure
        }),
        fcFastConfig
      );
    });

    test('divP vs. multP with negative exponent', () => {
      fc.assert(
        fc.property(
          elementModQ(context),
          elementModQ(context),
          elementModQ(context),
          (x, c, r) => {
            const gx = context.gPowP(x);
            const gr = context.gPowP(r);
            const negC = negateQ(c);
            const cr = multQ(c, r);
            const gcr = context.gPowP(cr);
            const xcr = addQ(x, cr);
            const gxcr = context.gPowP(xcr);
            const gx_div = divP(gxcr, gcr);
            expect(gx_div).toEqual(gx);

            const invGcr = powP(gr, negC);
            expect(multInvP(gcr)).toEqual(invGcr);

            const gx_mul = multP(gxcr, invGcr);
            expect(gx_div).toEqual(gx_mul);
          }
        ),
        fcFastConfig
      );
    });

    test('divP vs. multP with negative exponent, v2', () => {
      fc.assert(
        fc.property(
          elementModQ(context),
          elementModQ(context),
          elementModQ(context),
          (x, c, r) => {
            const gr = context.gPowP(r);
            const gxPlain = context.gPowP(x);

            const gxcInvPlain = powP(gxPlain, negateQ(c));
            const gxcInv2Plain = multInvP(powP(gxPlain, c));
            expect(gxcInvPlain).toEqual(gxcInv2Plain);

            const a1 = multP(gr, powP(gxPlain, negateQ(c)));
            const a2 = divP(gr, powP(gxPlain, c));
            expect(a1).toEqual(a2);

            const gxAccel = gxPlain.acceleratePow();

            const gxcInvAccel = powP(gxAccel, negateQ(c));
            const gxcInv2Accel = multInvP(powP(gxAccel, c));
            expect(gxcInvAccel).toEqual(gxcInv2Accel);

            const a3 = multP(gr, powP(gxAccel, negateQ(c)));
            const a4 = divP(gr, powP(gxAccel, c));

            expect(a3).toEqual(a4);
            expect(a1).toEqual(a3);
          }
        ),
        fcFastConfig
      );
    });

    test('divP vs. multP with negative exponent, v2, just the generator', () => {
      fc.assert(
        fc.property(elementModQ(context), elementModQ(context), (c, r) => {
          const gxPlain = context.createElementModP(context.G) || fail();
          const gr = powP(gxPlain, r);

          const gxcInvPlain = powP(gxPlain, negateQ(c));
          const gxcInv2Plain = multInvP(powP(gxPlain, c));
          expect(gxcInvPlain).toEqual(gxcInv2Plain);

          const a1 = multP(gr, powP(gxPlain, negateQ(c)));
          const a2 = divP(gr, powP(gxPlain, c));
          expect(a1).toEqual(a2);

          const gxAccel = gxPlain.acceleratePow();

          const gxcInvAccel = powP(gxAccel, negateQ(c));
          const gxcInv2Accel = multInvP(powP(gxAccel, c));
          expect(gxcInvAccel).toEqual(gxcInv2Accel);

          const a3 = multP(gr, powP(gxAccel, negateQ(c)));
          const a4 = divP(gr, powP(gxAccel, c));

          expect(a3).toEqual(a4);
          expect(a1).toEqual(a3);
        }),
        fcFastConfig
      );
    });

    test('serialization', () => {
      fc.assert(
        fc.property(elementModP(context), a => {
          expect(context.createElementModPFromHex(a.toHex())).toEqual(a);
        })
      );
    });
  });
}

testGroup(bigIntContext4096());
testGroup(bigIntContext3072());

test('compatibleContextOrFail', () => {
  const context1 = bigIntContext3072();
  const context2 = bigIntContext4096();
  expect(() => compatibleContextOrFail()).toThrow();
  expect(compatibleContextOrFail(context1.randQ(), context1.randQ()).name).toBe(
    context1.name
  );
  expect(() =>
    compatibleContextOrFail(context1.randQ(), context2.randQ())
  ).toThrow();
});
