import assert from "node:assert/strict";
import test from "node:test";
import { StorageQuotaError } from "../core/storage.js";
import { FAILURE_CODES, workflowFailureCode } from "../workflow/failure.js";

test("workflow diagnostics use bounded fixed codes without copying exception data", () => {
  assert.equal(workflowFailureCode(new Error("workflow input root changed after scanning")), "input-root-changed");
  assert.equal(workflowFailureCode(new Error("workflow scan did not complete without errors")), "scan-completed-with-errors");
  assert.equal(workflowFailureCode(new Error("wrapper", {cause: new Error("lsblk did not return the requested source device")})), "source-device-identity-unresolved");
  const sensitive = new Error("synthetic confidential value at /private/source");
  sensitive.cause = sensitive;
  assert.equal(workflowFailureCode(sensitive), "unclassified-failure");
  assert.equal(workflowFailureCode({message: "workflow input root changed after scanning"}), "unclassified-failure");
});

test("workflow diagnostics report fixed reasons for typed quota errors", () => {
  const capacity = {availableBytes: 5n, totalBytes: 100n, reservedBytes: 10n, outputBytes: 2n, plannedBytes: 1n};
  for (const reason of ["free-space-reserve", "output-cap"] as const) {
    const quota = new StorageQuotaError(reason, capacity);
    assert.equal(workflowFailureCode(new Error("synthetic recovery wrapper", {cause: quota})), reason);
    assert.equal(FAILURE_CODES.has(reason), true);
    assert.equal(workflowFailureCode(new Error(quota.message)), "unclassified-failure");
  }
});

test("a native quota error survives recovery report and lock-release error wrappers", () => {
  const quota = new StorageQuotaError("free-space-reserve",
    {availableBytes: 5n, totalBytes: 100n, reservedBytes: 10n, outputBytes: 2n, plannedBytes: 1n});
  const native = new Error("synthetic recovery stop", {cause: quota});
  const report = new AggregateError([native, new Error("synthetic report error")], "synthetic report wrapper");
  const release = new AggregateError([report, new Error("synthetic lock release error")], "synthetic lock wrapper");
  assert.equal(workflowFailureCode(release), "free-space-reserve");

  const cyclic = new AggregateError([], "synthetic cycle");
  cyclic.errors.push(cyclic, new Error("unrecognized synthetic diagnostic"));
  assert.equal(workflowFailureCode(cyclic), "unclassified-failure");
});
