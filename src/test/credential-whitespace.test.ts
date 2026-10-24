import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { detectConfigurationSecrets } from "../mining/detectors/config-secrets.js";
import { detectProviderCredentials } from "../mining/detectors/providers.js";
import { DetectorWorkerPool } from "../mining/worker-pool.js";

for (const [module, detector] of [
  ["providers", "detectProviderCredentials"],
  ["config-secrets", "detectConfigurationSecrets"],
] as const) {
  test(`${module} detection finishes on large runs of blank lines without assignments`, () => {
    const detectorUrl = new URL(`../mining/detectors/${module}.js`, import.meta.url).href;
    const script = `
      import { ${detector} as detect } from ${JSON.stringify(detectorUrl)};
      for (const blank of ${JSON.stringify(["\r\n \t", "\r", "\n"])}) {
        const data = Buffer.from(blank.repeat(250000) + "!");
        if (!data.includes(0x0a) && !data.includes(0x0d)) process.exit(2);
        const found = detect(data, { sourcePath: "/synthetic", baseOffset: 0, wholeFile: false });
        if (found.length !== 0) process.exit(1);
      }
    `;
    // This generous hang guard is enforceable even inside a native regexp;
    // it is not a throughput target for the detector.
    const result = spawnSync(process.execPath, ["--input-type=module", "--eval", script], {
      encoding: "utf8",
      timeout: 30000,
      killSignal: "SIGKILL",
    });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
  });
}

test("multiline assignment whitespace preserves exact values and source offsets", () => {
  const value = "synthetic-value-12345";
  for (const delimiter of ["\n", "\r", ",", "{", ";"]) {
    for (const whitespace of ["", " \t", "\r\n\r\n \t", "\n".repeat(1000)]) {
      const input = Buffer.from(`prefix${delimiter}${whitespace}"password" = "${value}"`);
      const found = detectProviderCredentials(input, { sourcePath: "/synthetic", baseOffset: 123, wholeFile: false });
      const assignments = found.filter(candidate => candidate.category === "secret-assignment");
      assert.equal(assignments.length, 1);
      assert.equal(assignments[0]?.offset, 123 + input.indexOf(value));
      assert.deepEqual(assignments[0]?.value, Buffer.from(value));
    }
  }
});

test("WireGuard and Kubernetes keys retain multiline whitespace support and exact offsets", () => {
  const wireGuard = Buffer.alloc(32, 0x5a).toString("base64");
  const { privateKey } = generateKeyPairSync("ed25519");
  const kubeKey = Buffer.from(privateKey.export({ type: "pkcs8", format: "pem" })).toString("base64");
  for (const blank of ["\r", "\n", "\r\n"]) {
    const whitespace = `${blank.repeat(1000)} \t`;
    const input = Buffer.from(`ordinary${blank}${whitespace}PrivateKey\r\n = \n${wireGuard}\r\n${whitespace}client-key-data:\r\n ${kubeKey}\r\n`);
    const found = detectConfigurationSecrets(input, { sourcePath: "/synthetic", baseOffset: 123, wholeFile: false });
    for (const [category, value] of [["wireguard-x25519-private-key", wireGuard], ["kubernetes-client-private-key-data", kubeKey]] as const) {
      const matches = found.filter(candidate => candidate.category === category);
      assert.equal(matches.length, 1);
      assert.equal(matches[0]?.offset, 123 + input.indexOf(value));
      assert.deepEqual(matches[0]?.value, Buffer.from(value));
    }
  }
});

test("whitespace-prefixed credentials preserve findings across worker counts", async () => {
  const value = "synthetic-value-12345";
  const wireGuard = Buffer.alloc(32, 0x5a).toString("base64");
  const { privateKey } = generateKeyPairSync("ed25519");
  const kubeKey = Buffer.from(privateKey.export({ type: "pkcs8", format: "pem" })).toString("base64");
  const inputs = [
    Buffer.from(`${"\r\n \t".repeat(1000)}"password" = "${value}"`),
    Buffer.from(`${"\r".repeat(1000)} PrivateKey = ${wireGuard}\r\n`),
    Buffer.from(`${"\n".repeat(1000)}\tclient-key-data: ${kubeKey}\r\n`),
    Buffer.from(`${"\r\n".repeat(1000)}!`),
  ];
  const run = async (workers: number) => {
    const pool = new DetectorWorkerPool(workers);
    try {
      const batches = await Promise.all(inputs.map((data, index) => pool.run("streaming", data, {
        sourcePath: "/synthetic",
        baseOffset: 123 + index * 10000,
        wholeFile: false,
      })));
      assert.ok(batches.flat().every(batch => batch.error === undefined));
      return batches;
    } finally {
      await pool.close();
    }
  };
  const single = await run(1);
  assert.deepEqual(await run(4), single);
  for (const [index, category, expectedValue] of [
    [0, "secret-assignment", value],
    [1, "wireguard-x25519-private-key", wireGuard],
    [2, "kubernetes-client-private-key-data", kubeKey],
  ] as const) {
    const found = single[index]?.flatMap(batch => batch.candidates).find(candidate => candidate.category === category);
    assert.ok(found);
    assert.equal(found.offset, 123 + index * 10000 + inputs[index]!.indexOf(expectedValue));
    assert.deepEqual(Buffer.from(found.value), Buffer.from(expectedValue));
  }
  assert.equal(single[3]?.flatMap(batch => batch.candidates).length, 0);
});
