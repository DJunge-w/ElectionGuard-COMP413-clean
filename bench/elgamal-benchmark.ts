import {
  ElGamalKeypair,
  ElGamalCiphertext,
  elGamalEncrypt,
} from '../src/electionguard/core/elgamal';
import {
  bigIntContext3072,
  bigIntContext4096,
} from '../src/electionguard/core/group-bigint';
import {GroupContext} from '../src/electionguard/core/group-common';
import { haclContext3072Async, haclContext4096Async } from '../src/electionguard/core/group-hacl';

function measureTimeMillis(f: () => void): number {
  const start = Date.now();
  f();
  const end = Date.now();
  return end - start;
}

function getRandomInt(min: number, max: number): number {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min) + min); //The maximum is exclusive and the minimum is inclusive
}

/**
 * A simple benchmark that just measures how fast ElGamal encryption runs
 */
function benchmarkElGamal(context: GroupContext) {
  console.log(`${context.name}: BenchmarkElgamal`);
  const N = 1000;

  const max = 100;
  const min = 0;
  console.log(`Initializing benchmark for ${N} attempts.`);

  const messages = Array.from({length: N}, () => getRandomInt(min, max));
  const keypair = ElGamalKeypair.createRandom(context);
  const nonce = context.randQ();

  console.log('Running!');
  // console.log(messages);
  const ciphertexts: ElGamalCiphertext[] = [];
  const encryptionTimeMs = measureTimeMillis(() => {
    messages.forEach(message =>
      ciphertexts.push(elGamalEncrypt(keypair, message, nonce))
    );
  });
  const encryptionTime = encryptionTimeMs / 1000.0;
  type plaintextType = number | undefined;
  const plaintexts: plaintextType[] = [];
  const decryptionTimeMs = measureTimeMillis(() => {
    ciphertexts.forEach(ciphertext =>
      plaintexts.push(ciphertext.decrypt(keypair))
    );
  });
  const decryptionTime = decryptionTimeMs / 1000.0;
  console.log(
    `ElGamal ${(N / encryptionTime).toFixed(2)} encryptions/sec, ${(
      N / decryptionTime
    ).toFixed(2)} decryptions/sec`
  );
  console.log();
}

benchmarkElGamal(bigIntContext3072());
benchmarkElGamal(bigIntContext4096());

haclContext3072Async().then(context => benchmarkElGamal(context));
haclContext4096Async().then(context => benchmarkElGamal(context));
