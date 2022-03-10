import {
    ElementModP,
    ONE_MOD_P,
    mult_p,
    G,
    g_pow_p,
    int_to_q,
    int_to_p_unchecked,
    int_to_q_unchecked,
    P
} from './group';
import * as bigintModArith from 'bigint-mod-arith'

import {
    get_optional
} from './utils';
// import {powmod} from './groupUtils';
import {discrete_log} from './dlog';

function _discrete_log_uncached(e: ElementModP): bigint {
    let count = 0;
    // const g_inv: ElementModP = int_to_p_unchecked(powmod(G, P));
    const g_inv: ElementModP = int_to_p_unchecked(bigintModArith.modPow(G, -1n, P));

    while (e.elem !== ONE_MOD_P.elem) {
        e = mult_p(e, g_inv);
        count += 1;
    }
    return BigInt(count);
}


describe("Test_DLog", () => {

    test("test_uncached", () => {
        const max = 100;
        const min = 0;
        const exp = BigInt(Math.floor(Math.random() * (max - min + 1) + min));
        const plaintext = get_optional(int_to_q(exp));
        const exp_plaintext = g_pow_p(plaintext);
        const plaintext_again = _discrete_log_uncached(exp_plaintext);

        expect(plaintext_again).toBe(exp);
    });

    test("test_cached", () => {
        const max = 1000;
        const min = 0;
        const exp = BigInt(Math.floor(Math.random() * (max - min + 1) + min));
        const plaintext = get_optional(int_to_q(exp))
        const exp_plaintext = g_pow_p(plaintext)
        const plaintext_again = discrete_log(exp_plaintext)

        expect(plaintext_again).toBe(exp);
    });

    test("test_cached_one", () => {
        const plaintext = int_to_q_unchecked(1n);
        const ciphertext = g_pow_p(plaintext);
        const plaintext_again = discrete_log(ciphertext);
        expect(plaintext_again).toBe(1n);
    });
})
