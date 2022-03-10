import {ElementModPOrQ, ElementModQ} from "./group"
import { hash_elems } from "./hash"


export class Nonces {
    __seed: ElementModQ;
    __idx = 0;
    public constructor(seed: ElementModQ, ...header: (ElementModPOrQ | string)[]) {
        if (header.length > 0) {
            const hash_lst:(ElementModPOrQ | string)[] = [seed,...header];
            this.__seed = hash_elems(hash_lst);
        }  else {
            this.__seed = seed;
        }
    }

    public get(index: number): ElementModQ {
        return this.get_with_headers(index);
    }

    public get_with_headers(item: number, ...headers: string[]): ElementModQ {
        const hash_lst:(ElementModQ | number | string)[] = [this.__seed,item];
        hash_lst.concat(headers);
        return hash_elems(hash_lst);
    }
    public next(): ElementModQ {
        const newNonce = this.get(this.__idx);
        this.__idx++;
        return newNonce;
    }

    public slice(start: number, end:number): ElementModQ[] {
        const return_list: ElementModQ[] = [];
        for(let i = start; i < end; i++) {
            return_list.push(this.get(i));
        }
        return return_list;
    }
}
