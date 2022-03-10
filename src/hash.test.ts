import {ElementModQ,
    ElementModP} from './group';
import {elements_mod_q,
    elements_mod_p} from './groupUtils'
import {hash_elems} from './hash';

describe("TestHash", () => {
    test('test_same_answer_twice_in_a_row', () => {
        const a: ElementModP = elements_mod_p();
        const b: ElementModQ = elements_mod_q();

        const h1:ElementModQ = hash_elems([a, b]);
        const h2:ElementModQ = hash_elems([a, b]);

        expect(h1.equals(h2)).toBe(true);
    });
    
    test('test_basic_hash_properties', () => {
        const a: ElementModQ = elements_mod_q();
        const b: ElementModQ = elements_mod_q();

        const ha:ElementModQ = hash_elems(a);
        const hb:ElementModQ = hash_elems(b);
        if (a.equals(b)) {
            expect(ha.equals(hb)).toBe(true);
        } else {
            expect(ha.notEqual(hb)).toBe(true);

        }
    });
    });