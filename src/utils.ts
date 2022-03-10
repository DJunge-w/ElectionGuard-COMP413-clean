// Util functions
// import {log_error} from './logs'
/**
 * General-purpose unwrapping function to handle `Optional`.
 * Raises an exception if it's actually `null or undefined`, otherwise
 * returns the internal type.
 * @param optional input that can be null or undefined.
 */
export function get_optional<T>(optional: T | undefined | null): T {
  if (optional !== null && optional !== undefined) {
    return optional;
  }
  throw new Error("Unwrap called on null or undefined.");
}

/**
 * General-purpose pattern-matching function to handle `Optional`.
 * If it's actually `null or undefined`, the `none_func` lambda is called.
 * Otherwise, the `some_func` lambda is called with the value.
 * @param optional input that can be null or undefined.
 * @param none_func function to be called if the optional is null or undefined.
 * @param some_func function to be called if the optional is not null or undefined.
 */
export function match_optional<T, U>(optional: T | null | undefined, none_func: ()=>U,
                                     some_func: (arg0: T)=>U): U {
  if (optional !== null && optional !== undefined) {
    return some_func(optional);
  } else {
    return none_func();
  }
}

/**
 * General-purpose getter for `Optional`. If it's `null or undefined`,
 * returns the `alt_value`. Otherwise, returns the contents of `optional`.
 * @param optional input that can be null or undefined.
 * @param alt_value returned value if optional is null or undefined.
 */
export function get_or_else_optional<T>(optional: T | null | undefined,
                                        alt_value: T): T {
 if (optional !== null && optional !== undefined) {
   return optional;
 } else {
   return alt_value;
 }
}

/**
 * General-purpose getter for `Optional`. If it's `null or undefined`,
 * calls the lambda `func` and returns its value. Otherwise, returns
 * the contents of `optional`.
 * @param optional input that can be null or undefined.
 * @param func function to be called if the optional is null or undefined.
 */
export function get_or_else_optional_func<T>(optional: T | null | undefined,
                                             func: ()=>T): T {
  if (optional !== null && optional !== undefined) {
    return optional;
  } else {
    return func();
  }
}

/**
 * General-purpose flatmapping on `Optional`. If it's `null or undefined`,
 * returns `None` as well, otherwise returns the lambda applied to the contents.
 * @param optional input that can be null or undefined.
 * @param mapper the lambda applied to the contents.
 */
export function flatmap_optional<T, U>(optional: T | undefined | null,
                                       mapper: ((arg0: T)=>U)): U | null | undefined {
  if (optional !== null && optional !== undefined) {
    return mapper(optional);
  } else {
    return undefined;
  }
}

/**
 * General-purpose cleanup of lists that might have None in them. If None is anywhere
 in the list, the result is None. Otherwise, we get back the list without `Optional`
 in its type parameter.
 * @param input array that might have null or undefined in them
 * @param err_msg msg to be logged when the array contains null or endefined
 */
export function list_of_option_to_option_list<T>(input: Array<T | undefined | null>,
                                                 err_msg = ""): Array<T> | undefined | null {
  if (!input.includes(undefined) && !input.includes(null)) {
    const result = input as Array<T>;
    return result;
  } else {
    if (err_msg !== "") {
      // log_error(err_msg);
    }
    return undefined;
  }
}
















