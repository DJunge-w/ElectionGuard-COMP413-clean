
import { bnToHex, getRandomIntExclusive, } from "./groupUtils";
import * as bigintModArith from 'bigint-mod-arith';
import {Type} from "class-transformer";
import "reflect-metadata";
// Constants used by ElectionGuard
// const Q = 32633n;
// const P = 65267n;
// const R = 2n;
// const G = 3n;
// const Q_MINUS_ONE = Q - 1n;


// // Large Test constants used by electionguard
// const Q = 65521n;
// const P = 18446744073704586917n;
// const R = 281539415968996n;
// const G = 15463152587872997502n;
// const Q_MINUS_ONE = Q - 1n;


const Q = BigInt('115792089237316195423570985008687907853269984665640564039457584007913129639747');
const P = BigInt('1044388881413152506691752710716624382579964249047383780384233483283953907971553643537729993126875883902173634017777416360502926082946377942955704498542097614841825246773580689398386320439747911160897731551074903967243883427132918813748016269754522343505285898816777211761912392772914485521155521641049273446207578961939840619466145806859275053476560973295158703823395710210329314709715239251736552384080845836048778667318931418338422443891025911884723433084701207771901944593286624979917391350564662632723703007964229849154756196890615252286533089643184902706926081744149289517418249153634178342075381874131646013444796894582106870531535803666254579602632453103741452569793905551901541856173251385047414840392753585581909950158046256810542678368121278509960520957624737942914600310646609792665012858397381435755902851312071248102599442308951327039250818892493767423329663783709190716162023529669217300939783171415808233146823000766917789286154006042281423733706462905243774854543127239500245873582012663666430583862778167369547603016344242729592244544608279405999759391099769165589722584216017468464576217318557948461765770700913220460557598574717173408252913596242281190298966500668625620138188265530628036538314433100326660047110143');
// // ((P - 1) * pow(Q, -1, P)) % P
// // rewrite pow(a,-b,c) as pow((a^-1) mod c, b, c)
const R = BigInt('9019518416950528558373478086511232658951474842525520401496114928154304263969655687927867442562559311457926593510757267649063628681241064260953609180947464800958467390949485096429653122916928704841547265126247408167856620024815508684472819746384115369148322548696439327979752948311712506113890045287907335656308945630141969472484100558565879585476547782717283106837945923693806973017510492730838409381014701258202694245760602718602550739205297257940969992371799325870179746191672464736721424617639973324090288952006260483222894269928179970153634220390287255837625331668555933039199194619824375869291271098935000699785346405055160394688637074599519052655517388596327473273906029869030988064607361165803129718773877185415445291671089029845994683414682274353665003204293107284473196033588697845087556526514092678744031772226855409523354476737660407619436531080189837076164818131039104397776628128325247709678431023369197272126578394856752060591013812807437681624251867074769638052097737959472027002770963255207757153746376691827309573603635608169799503216990026029763868313819255248026666854405409059422844776556067163611304891154793770115766608153679099327786')
// const R: bigint = ((P - BigInt(1)) * bigintModArith.modPow(Q, -1, P)) % P;
// // const R: bigint = ((P - 1n) * (powmod(Q, P) % P)) % P;
const G  = BigInt('119359756198641231858139651428439585561105914902686985078252796680474637856752833978884422594516170665312423393830118608408063594508087813277769835084746883589963798527237870817233369094387978405585759195339509768803496494994109693743279157584139079471178850751266233150727771094796709619646350222242437970473900636242584673413224137139139346254912172628651028694427789523683070264102332413084663100402635889283790741342401259356660761075766365672754329863241692760862540151023800163269173550320623249398630247531924855997863109776955214403044727497968354022277828136634059011708099779241302941071701051050378539485717425482151777277387633806111112178267035315726401285294598397677116389893642725498831127977915200359151833767358091365292230363248410124916825814514852703770457024102738694375502049388804979035628232209959549199366986471874840784466132903083308458356458177839111623113116525230200791649979270165318729763550486200224695556789081331596212761936863634467236301450039399776963661755684863012396788149479256016157814129329192490798309248914535389650594573156725696657302152874510063002532052622638033113978672254680147128450265983503193865576932419282003012093526302631221491418211528781074474515924597472841036553107847');
const Q_MINUS_ONE: bigint = Q - BigInt(1);

// Large const in electionguard python

const mod: (a: bigint, b: bigint) => bigint = (a, b) => {
    return ((a % b) + b) % b
}


class ElementModQ {
    // An element of the smaller `mod q` space, i.e., in [0, Q), where Q is a 256-bit prime.
    @Type(() => BigInt)
    public elem: bigint;

    constructor(elem: bigint | number) {
      if (typeof elem === "bigint") {
        this.elem = elem;
      } else {
        this.elem = BigInt(elem);
      }
    }

    // TODO: Probably don't need this function since it's not used anywhere else in the code base
    // Converts from the element to the representation of bytes by first going through hex.
    // This is preferable to directly accessing `elem`, whose representation might change.
    public to_bytes(): bigint {
        // return base16decode(this.bnToHex(this.elem));
        return BigInt(0);
    }

    // Converts from the element to the hex representation of bytes. This is preferable to directly
    // accessing `elem`, whose representation might change.
    public to_hex(): string {
        return bnToHex(this.elem);
    }

    // Converts from the element to a regular integer. This is preferable to directly
    // accessing `elem`, whose representation might change.
    public to_int(): bigint {
        return this.elem;
    }

    // Validates that the element is actually within the bounds of [0,Q).
    // Returns true if all is good, false if something's wrong.
    public is_in_bounds(): boolean {
        return 0 <= this.elem && this.elem < Q;
    }

    // Validates that the element is actually within the bounds of [1,Q).
    // Returns true if all is good, false if something's wrong.
    public is_in_bounds_no_zero(): boolean {
        return 0 < this.elem && this.elem < Q;
    }

    // Operator overloading not supported in TypeScript, need to call the function instead
    public notEqual(other: ElementModPOrQ): boolean {
        return (other instanceof ElementModP || other instanceof ElementModQ) && !eq_elems(this, other);
    }

    // overload == (equal to) operator
    public equals(other: ElementModPOrQ): boolean {
        return (other instanceof ElementModP || other instanceof ElementModQ) && eq_elems(this, other);
    }

    public toString(): string {
        return this.elem.toString();
    }

    public hashCode(): bigint {
        return createStrHashCode(this.elem.toString());
    }

    toJSON():string {
        // return this.elem.toString().toUpperCase();
        return this.elem.toString(16).toUpperCase();

    }

    // TODO: Not sure if this is needed in TypeScript version
    // # __getstate__ and __setstate__ are here to support pickle and other serialization libraries.
    // # These are intended for use in "trusted" environments (e.g., running on a computational cluster)
    // # but should not be used when reading possibly untrusted data from a file. For that, use functions
    // # like int_to_p(), which will return None if there's an error.

    // def __getstate__(self) -> dict:
    //     return {"elem": int(self.elem)}

    // def __setstate__(self, state: dict) -> None:
    //     if "elem" not in state or not isinstance(state["elem"], int):
    //         raise AttributeError("couldn't restore state, malformed input")
    //     self.elem = mpz(state["elem"])
}

class ElementModP {
    // An element of the larger `mod p` space, i.e., in [0, P), where P is a 4096-bit prime.
    public elem: bigint;

    constructor(elem: bigint) {
        this.elem = elem;
    }

    // Converts from the element to the hex representation of bytes. This is preferable to directly
    // accessing `elem`, whose representation might change.
    public to_hex(): string {
        return bnToHex(this.elem);
    }

    public to_int(): bigint {
        return this.elem;
    }

    public is_in_bounds(): boolean {
        return 0 <= this.elem && this.elem < P;
    }

    public is_in_bounds_no_zero(): boolean {
        return 0 < this.elem && this.elem < P;
    }

    public is_valid_residue(): boolean {
        const residue: boolean = pow_p(this, new ElementModQ(BigInt(Q))).equals(ONE_MOD_P);
        return this.is_in_bounds() && residue;
    }

    public notEqual(other: ElementModPOrQ): boolean {
        return (other instanceof ElementModP || other instanceof ElementModQ) && !eq_elems(this, other);
    }

    public equals(other: ElementModPOrQ): boolean {
        return (other instanceof ElementModP || other instanceof ElementModQ) && eq_elems(this, other);
    }

    public toString(): string {
        return this.elem.toString();
    }

    public hashCode(): bigint {
        return createStrHashCode(this.elem.toString());
    }


    toJSON():string {
      return this.elem.toString(16).toUpperCase();
    //   return this.elem.toString().toUpperCase();

    }
    // def __getstate__(self) -> dict:
    //     return {"elem": int(self.elem)}

    // def __setstate__(self, state: dict) -> None:
    //     if "elem" not in state or not isinstance(state["elem"], int):
    //         raise AttributeError("couldn't restore state, malformed input")
    //     self.elem = mpz(state["elem"])

}

// Common constants
const ZERO_MOD_Q: ElementModQ = new ElementModQ(BigInt(0));
const ONE_MOD_Q: ElementModQ = new ElementModQ(BigInt(1));
const TWO_MOD_Q: ElementModQ = new ElementModQ(BigInt(2));

const ZERO_MOD_P: ElementModP = new ElementModP(BigInt(0));
const ONE_MOD_P: ElementModP = new ElementModP(BigInt(1));
const TWO_MOD_P: ElementModP = new ElementModP(BigInt(2));
const G_MOD_P: ElementModP = new ElementModP(G);

type ElementModPOrQ = ElementModP | ElementModQ;
type ElementModPOrQorInt = ElementModP | ElementModQ | bigint;
type ElementModQorInt = ElementModQ | bigint;
type ElementModPorInt = ElementModP | bigint;



// Given a hex string representing bytes, returns an ElementModQ.
// Returns `None` if the bigint is out of the allowed
// [0,Q) range.
// Reference: https://stackoverflow.com/questions/14667713/how-to-convert-a-string-to-bigint-in-typescript
const hex_to_q: (input: string) => ElementModQ | null = (input) => {
    const i = BigInt(input);
    if (0 <= i && i < Q) {
        return new ElementModQ(BigInt(i));
    } else {
        return null;
    }
}

// Given an integer, returns an ElementModQ.
// Returns `None` if the bigint is out of the allowed
// [0,Q) range.
const int_to_q: (input: string | bigint) => ElementModQ | null = (input) => {
    const i = BigInt(input);
    if (0 <= i && i < Q) {
        return new ElementModQ(BigInt(i));
    } else {
        return null;
    }
}

// Given an integer, returns an ElementModQ. Allows
// for the input to be out-of-bounds, and thus creating an invalid
// element (i.e., outside of [0,Q)). Useful for tests of it
// you're absolutely, positively, certain the input is in-bounds.
const int_to_q_unchecked: (i: string | bigint) => ElementModQ = (i) => {
    return new ElementModQ(BigInt(i));
}

// Given an integer, returns an ElementModP.
// Returns `None` if the bigint is out of the allowed
// [0,P) range.
const int_to_p: (input: string | bigint) => ElementModP | null = (input) => {
    const i = BigInt(input);
    if (0 <= i && i < P) {
        return new ElementModP(BigInt(i));
    } else {
        return null;
    }
}

// Given an integer, returns an ElementModP. Allows
//     for the input to be out-of-bounds, and thus creating an invalid
//     element (i.e., outside of [0,P)). Useful for tests or if
//     you're absolutely, positively, certain the input is in-bounds.
const int_to_p_unchecked: (i: string | bigint) => ElementModP = (i) => {
    return new ElementModP(BigInt(i));
}

//TODO: what is bytes in python equivalent of?
// const qToBytes: (e: ElementModQ) => [] = (e) => {
//     return [];
// }

// TODO
// const bytesToQ: (b: []) => ElementModQ = (b) => {
//     return new ElementModQ(BigInt(0));
// }

const add_q: (...elems: ElementModQorInt[]) => ElementModQ = (...elems) => {
    let t = BigInt(0);
    elems.forEach((e) => {
        if (typeof e === 'bigint') {
            e = int_to_q_unchecked(e);
        }
        t = (t + e.elem) % BigInt(Q);
    });
    return new ElementModQ(t);
}

const a_minus_b_q: (a: ElementModQorInt, b: ElementModQorInt) => ElementModQ = (a, b) => {
    if (typeof a === 'bigint') {
        a = int_to_q_unchecked(a);
    }
    if (typeof b === 'bigint') {
        b = int_to_q_unchecked(b);
    }
    return new ElementModQ(mod((a.elem - b.elem),BigInt(Q)))
}

// Computes a/b mod p
const div_p: (a: ElementModPOrQorInt, b: ElementModPOrQorInt) => ElementModP = (a, b) => {
    if (typeof a === 'bigint') {
        a = int_to_p_unchecked(a);
    }
    if (typeof b === 'bigint') {
        b = int_to_p_unchecked(b);
    }

    // Calculate modular multiplicative inverse in typescript
    // bigintModArith.modPow(Q, -1, P)
    const inverse = bigintModArith.modPow(b.elem, -1, P);
    // const inverse = powmod(b.elem, P);
    return mult_p(a, int_to_p_unchecked(inverse));
}

// Computes a/b mod q
const div_q: (a: ElementModPOrQorInt, b: ElementModPOrQorInt) => ElementModQ = (a, b) => {
    if (typeof a === 'bigint') {
        a = int_to_q_unchecked(a);
    }
    if (typeof b === 'bigint') {
        b = int_to_q_unchecked(b);
    }

    // Calculate modular multiplicative inverse in typescript

    const inverse = bigintModArith.modPow(b.elem, -1, Q);
    // const inverse = powmod(b.elem, Q);
    return mult_q(a, int_to_q_unchecked(inverse));
}

// Computes (Q - a) mod q.
const negate_q: (a: ElementModQorInt) => ElementModQ = (a) => {
    if (typeof a === 'bigint') {
        a = int_to_q_unchecked(a);
    }
    return new ElementModQ(BigInt(Q) - a.elem);
}

// Computes (a + b * c) mod q.
const a_plus_bc_q: (a: ElementModQorInt, b: ElementModQorInt, c: ElementModQorInt) => ElementModQ = (a, b, c) => {
    if (typeof a === 'bigint') {
        a = int_to_q_unchecked(a);
    }
    if (typeof b === 'bigint') {
        b = int_to_q_unchecked(b);
    }
    if (typeof c === 'bigint') {
        c = int_to_q_unchecked(c);
    }
    return new ElementModQ((a.elem + b.elem * c.elem) % BigInt(Q));
}

// Computes the multiplicative inverse mod p.
// e:  An element in [1, P).
const mult_inv_p: (e: ElementModPOrQorInt) => ElementModP = (e) => {
    if (typeof e === 'bigint') {
        e = int_to_p_unchecked(e);
    }
    if (e.elem === BigInt(0)) throw(new Error("No multiplicative inverse for zero"));
    // return new ElementModP(powmod(e.elem, P));
    return new ElementModP(bigintModArith.modPow(e.elem, -1, P));
}

// Computes b^e mod p.
// b: An element in [0,P).
// e: An element in [0,P).
const pow_p: (b: ElementModPOrQorInt, e: ElementModPOrQorInt) => ElementModP = (b, e) => {
    if (typeof b === 'bigint') {
        b = int_to_p_unchecked(b);
    }
    if (typeof e === 'bigint') {
        e = int_to_p_unchecked(e);
    }
    return new ElementModP(bigintModArith.modPow(b.elem,e.elem,BigInt(P)));
}

// Computes b^e mod p.
// b: An element in [0,Q).
// e: An element in [0,Q).
const pow_q: (b: ElementModQorInt, e: ElementModQorInt) => ElementModQ = (b, e) => {
    if (typeof b === 'bigint') {
        b = int_to_q_unchecked(b);
    }
    if (typeof e === 'bigint') {
        e = int_to_q_unchecked(e);
    }

    return new ElementModQ(bigintModArith.modPow(b.elem, e.elem, BigInt(Q)));
}

// Computes the product, mod p, of all elements.
// elems: Zero or more elements in [0,P).
const mult_p: (...elems: ElementModPOrQorInt[]) => ElementModP = (...elems) => {
    let product = BigInt(1);
    elems.forEach((x) => {
        if (typeof x === 'bigint') {
            x = int_to_p_unchecked(x);
        }
        product = (product * x.elem) % P;
    })
    return new ElementModP(product);
}

// Computes the product, mod q, of all elements.
// elems: Zero or more elements in [0,P).
const mult_q: (...elems: ElementModPOrQorInt[]) => ElementModQ = (...elems) => {
    let product = BigInt(1);
    elems.forEach((x) => {
        if (typeof x === 'bigint') {
            x = int_to_q_unchecked(x);
        }
        product = (product * x.elem) % BigInt(Q);
    })
    return new ElementModQ(product);
}

// Computes g^e mod p.
// e: An element in [0,P).
const g_pow_p: (e: ElementModPOrQ) => ElementModP = (e) => {
    return pow_p(G_MOD_P, e);
}

// Generate random bigint between 0 and Q
// return: Random value between 0 and Q
const rand_q: () => ElementModQ = () => {
    return int_to_q_unchecked(getRandomIntExclusive(Q));
}

// Generate random bigint between start and Q
// start: Starting value of range
// return: Random value between start and Q
const rand_range_q: (start: ElementModQorInt) => ElementModQ = (start) => {
    if (start instanceof ElementModQ) {
        start = start.to_int();
    }
    let random = BigInt(0);
    while (random < start) {
        random = getRandomIntExclusive(Q);
    }
    return int_to_q_unchecked(random);
}

const eq_elems: (a: ElementModPOrQ, b: ElementModPOrQ) => boolean = (a, b) => {
    return a.elem === b.elem;
}

////////// Utils only used in this file ////////////
// Manually hash a string, code taken from https://gist.github.com/hyamamoto/fd435505d29ebfa3d9716fd2be8d42f0
// The hash value of the empty string is zero.
const createStrHashCode: (s: string) => bigint = (s) => {
    let h = BigInt(0);
    for(let i = 0; i < s.length; i++) {
        h = BigInt(31) * h + BigInt(s.charCodeAt(i)) | BigInt(0);
    }
    return h;
}


const parseBigInt: (bigint:string, base: number) => Array<number> = (bigint, base) => {
    //convert bigint string to array of digit values
    const values = [];
    for (let i = 0; i < bigint.length; i++) {
      values[i] = parseInt(bigint.charAt(i), base);
    }
    return values;
  }

  const formatBigInt: (values:Array<number> , base:number) => string = (values, base) =>{
    //convert array of digit values to bigint string
    let bigint = '';
    for (let i = 0; i < values.length; i++) {
      bigint += values[i].toString(base);
    }
    return bigint;
  }

  const convertBase: (bigint:string, inputBase:number, outputBase:number)  => string = (bigint, inputBase, outputBase) => {
    //takes a bigint string and converts to different base
    const inputValues = parseBigInt(bigint, inputBase),
      outputValues = [], //output array, little-endian/lsd order
      len = inputValues.length;
    let pos = 0;
    while (pos < len) { //while digits left in input array
      let remainder = 0; //set remainder to 0
      for (let i = pos; i < len; i++) {
        //long integer division of input values divided by output base
        //remainder is added to output array
        remainder = inputValues[i] + remainder * inputBase;
        inputValues[i] = Math.floor(remainder / outputBase);
        remainder -= inputValues[i] * outputBase;
        if (inputValues[i] == 0 && i == pos) {
          pos++;
        }
      }
      outputValues.push(remainder);
    }
    outputValues.reverse(); //transform to big-endian/msd order
    return formatBigInt(outputValues, outputBase);
  }

  const groupDigits: (bigint:string) => string = (bigint) => {//3-digit grouping
    return bigint.replace(/(\d)(?=(\d{3})+$)/g, "$1 ");
  }



export {ElementModP, ElementModQ, P, Q, ONE_MOD_P, ZERO_MOD_P, ZERO_MOD_Q, ONE_MOD_Q, G, R, Q_MINUS_ONE, TWO_MOD_P, TWO_MOD_Q, ElementModPOrQ, ElementModPOrQorInt, ElementModQorInt, ElementModPorInt, hex_to_q, int_to_q, int_to_q_unchecked, int_to_p, int_to_p_unchecked, add_q, a_minus_b_q, div_p, div_q, negate_q, a_plus_bc_q, mult_inv_p, pow_p, pow_q, mult_p, mult_q, g_pow_p, rand_q, rand_range_q, eq_elems, convertBase, groupDigits, formatBigInt, parseBigInt};
