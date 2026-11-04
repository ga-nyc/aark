import assert from "node:assert/strict";
import test from "node:test";
import { workflowFailureCode } from "../workflow/failure.js";

test("workflow diagnostics use bounded fixed codes without copying exception data", () => {
  assert.equal(workflowFailureCode(new Error("workflow input root changed after scanning")), "input-root-changed");
  assert.equal(workflowFailureCode(new Error("wrapper", {cause: new Error("lsblk did not return the requested source device")})), "source-device-identity-unresolved");
  const sensitive = new Error("synthetic confidential value at /private/source");
  sensitive.cause = sensitive;
  assert.equal(workflowFailureCode(sensitive), "unclassified-failure");
  assert.equal(workflowFailureCode({message: "workflow input root changed after scanning"}), "unclassified-failure");
});
