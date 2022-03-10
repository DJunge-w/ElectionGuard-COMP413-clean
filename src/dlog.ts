// support for computing discrete logs, with a cache so they're never recomputed
import {G, ElementModP, ONE_MOD_P, mult_p, int_to_p_unchecked, P} from './group'
import * as bigintModArith from "bigint-mod-arith";
import {get_optional} from "./utils";

const __dlog_cache: Map<ElementModP, bigint> = new Map([[ONE_MOD_P, BigInt(0)]]);
let __dlog_max_elem:ElementModP = ONE_MOD_P;
let __dlog_max_exp = BigInt(0);

// let __dlog_lock: = undefined;

function _discrete_log_uncached(e: ElementModP): bigint {
  let count = 0;
  // const g_inv: ElementModP = int_to_p_unchecked(powmod(G, P));
  const g_inv: ElementModP = int_to_p_unchecked(bigintModArith.modPow(G, -BigInt(1), P));

  while (e.elem !== ONE_MOD_P.elem) {
    e = mult_p(e, g_inv);
    count += 1;
  }
  return BigInt(count);
}


//TODO: this implementation is not actually multi-threaded, the lock mechanism is currently not found
export function discrete_log(e: ElementModP): bigint {
  if (__dlog_cache.has(e)) {
    return get_optional(__dlog_cache.get(e));
  } else {
    return _discrete_log_uncached(e);
  }
}

export function __discrete_log_internal(e: ElementModP): bigint {
  const g = int_to_p_unchecked(G);
  while (e !== __dlog_max_elem) {
    __dlog_max_exp = __dlog_max_exp + BigInt(1);
    __dlog_max_elem = mult_p(g, __dlog_max_elem);
    __dlog_cache.set(__dlog_max_elem, __dlog_max_exp);
  }
  return get_optional(__dlog_cache.get(__dlog_max_elem));
}
