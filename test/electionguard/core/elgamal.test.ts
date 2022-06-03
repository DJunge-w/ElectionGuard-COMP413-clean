import * as fc from 'fast-check';
import {elementModQ, elGamalKeypair, fcFastConfig} from './generators';
import {
  elGamalAdd,
  elGamalEncrypt,
} from '../../../src/electionguard/core/elgamal';
import {
  bigIntContext3072Async,
  bigIntContext4096Async,
} from '../../../src/electionguard/core/group-bigint';
import {GroupContext} from '../../../src/electionguard/core/group-common';
import {
  haclContext3072Async,
  haclContext4096Async,
} from '../../../src/electionguard/core/group-hacl';

function testElGamal(
  contextName: string,
  contextPromise: Promise<GroupContext>
) {
  let context: GroupContext;
  describe(`${contextName}: ElGamal properties`, () => {
    beforeAll(async () => {
      context = await contextPromise;
    });

    test('encryption/decryption', () => {
      fc.assert(
        fc.property(
          elGamalKeypair(context),
          fc.nat(1000),
          fc.nat(1000),
          elementModQ(context, 2),
          elementModQ(context, 2),
          (keypair, p1, p2, nonce1, nonce2) => {
            const c1 = elGamalEncrypt(keypair, p1, nonce1);
            const p1a = c1.decrypt(keypair);
            expect(p1a).toEqual(p1); // decryption is the inverse of encryption

            const c2 = elGamalEncrypt(keypair, p2, nonce2);
            const p2a = c2.decryptWithNonce(keypair, nonce2);
            expect(p2a).toEqual(p2);

            // different nonces or different plaintexts yield different ciphertexts
            expect(c1.equals(c2)).toBe(nonce1.equals(nonce2) && p1 === p2);

            const c3 = elGamalAdd(c1, c2);
            const p3a = c3.decrypt(keypair);

            // homomorphic accumulation should be the same as plaintext accumulation
            expect(p3a).toEqual(p1 + p2);
          }
        ),
        fcFastConfig
      );
    });
  });
}

testElGamal('BigIntContext-3072', bigIntContext3072Async());
testElGamal('BigIntContext-4096', bigIntContext4096Async());
testElGamal('HaclContext-3072', haclContext3072Async());
testElGamal('HaclContext-4096', haclContext4096Async());
