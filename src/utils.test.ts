import {get_optional,
  match_optional,
  get_or_else_optional,
  flatmap_optional} from "./utils";

describe("TestUtils", () => {
  test("test_unwrap", () => {
    const good: number | undefined = 3;
    const bad: number | undefined = undefined;
    expect(get_optional(good)).toBe(3);
    // expect(get_optional(bad)).toThrowError("Unwrap called on null or undefined.");
    expect(() => {get_optional(bad);}).toThrowError();
  });

  test("test_match", () => {
    const good: number | undefined = 3;
    const bad: number | undefined = undefined;

    expect(match_optional(good, ()=> 1,
      (x: number) => x + 2)).toBe(5);
    expect(match_optional(bad, ()=> 1,
      (x: number) => x + 2)).toBe(1);
  });

  test("test_get_or_else", ()=> {
   const good: number | undefined = 3;
   const bad: number | undefined = undefined;

   expect(get_or_else_optional(good, 5)).toBe(3);
   expect(get_or_else_optional(bad, 5)).toBe(5);
  });

  test("test_flatmap", ()=> {
    const good: number | undefined = 3;
    const bad: number | undefined = undefined;

    expect(get_optional(flatmap_optional(good,
      (x) => x + 2))).toBe(5);
    expect(flatmap_optional(bad, (x:number) => x + 2)).toBeUndefined();
  })
});
