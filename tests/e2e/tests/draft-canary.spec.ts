import { expect, test } from "../src/fixtures.js";

const CANARY_PATH = "/projects/draft-canary/";
const CANARY_TITLE = "__draft_canary__";

/** Counts non-overlapping occurrences of needle in text. */
function countOccurrences(text: string, needle: string): number {
  return text.split(needle).length - 1;
}

test("draft canary page is not served", async ({ preview }) => {
  const response = await preview.get(CANARY_PATH);
  expect(response.status(), "status of the draft canary page").toBe(404);
});

test("top page does not contain the draft canary title", async ({ preview }) => {
  const response = await preview.get("/");
  expect(response.status(), "status").toBe(200);
  const count = countOccurrences(await response.text(), CANARY_TITLE);
  expect(count, "occurrences of the draft canary title on the top page").toBe(0);
});
