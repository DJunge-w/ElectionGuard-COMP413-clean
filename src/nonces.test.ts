import {ElementModQ,
    // ElementModP,
    // elements_mod_p,
    // int_to_q_unchecked
} from './group';
import {    elements_mod_q} from './groupUtils'
// import {hash_elems} from './hash';
import {Nonces} from './nonces';

describe("TestNonces", () => {
    test('test_nonces_iterable', () => {
        const seed:ElementModQ = elements_mod_q();
        const n = new Nonces(seed);
        const i: number = Math.floor(Math.random() * 100) + 1;
        const q0: ElementModQ = n.get(i);
        const q1: ElementModQ = n.get(i);
        expect(q0.equals(q1)).toBeTruthy();
    });

    test('test_nonces_deterministic', () => {
        const seed:ElementModQ = elements_mod_q();
        const i: number = Math.floor(Math.random() * 1000000) + 1;
        const n1:Nonces = new Nonces(seed);
        const n2:Nonces = new Nonces(seed);

        expect(n1.get(i).equals(n2.get(i))).toBeTruthy();
    });

    test('test_nonces_seed_matters', () => {
        let seed1:ElementModQ = elements_mod_q();
        let seed2:ElementModQ = elements_mod_q();
        const i: number = Math.floor(Math.random() * 1000000) + 1;
        while (seed1.equals(seed2)) {
            seed1 = elements_mod_q();
            seed2 = elements_mod_q();
        }
        const n1:Nonces = new Nonces(seed1);
        const n2:Nonces = new Nonces(seed2);
        expect(n1.get(i).equals(n2.get(i))).toBeFalsy();
    });

    test('test_nonces_with_slices', () => {
        const seed:ElementModQ = elements_mod_q();
        const n:Nonces = new Nonces(seed);
        const l:ElementModQ[] = [];  
        for (let i = 0; i < 10; i++) {
            l.push(n.get(i));
          }
        expect(l.length).toBe(10);
    });

    // test('test_nonces_type_errors', () => {
    //     const seed:ElementModQ = int_to_q_unchecked(3n);
        
    //     expect(new Nonces(seed)).toThrowError();
    // });

});
