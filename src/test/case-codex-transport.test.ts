import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { CodexPipeTransport } from "../case/codex-transport.js";

function frame(payload: Buffer | string, opcode = 1, final = true): Buffer {
  const value = typeof payload === "string" ? Buffer.from(payload) : payload;
  const header = Buffer.alloc(value.length < 126 ? 2 : value.length < 65536 ? 4 : 10);
  header[0] = (final ? 128 : 0) | opcode;
  header[1] = header.length === 2 ? value.length : header.length === 4 ? 126 : 127;
  if (header.length === 4) header.writeUInt16BE(value.length, 2);
  else if (header.length === 10) header.writeBigUInt64BE(BigInt(value.length), 2);
  return Buffer.concat([header, value]);
}
function clientFrame(value: Buffer): {opcode: number; payload: Buffer} {
  assert.ok((value[1]! & 128) !== 0, "every client frame uses a mask");
  let length = value[1]! & 127, offset = 2;
  if (length === 126) { length = value.readUInt16BE(2); offset = 4; }
  else if (length === 127) { length = Number(value.readBigUInt64BE(2)); offset = 10; }
  assert.equal(value.length, offset + 4 + length);
  const mask = value.subarray(offset, offset + 4), payload = Buffer.from(value.subarray(offset + 4));
  for (let i = 0; i < payload.length; i++) payload[i] = payload[i]! ^ mask[i % 4]!;
  return {opcode: value[0]! & 15, payload};
}
function fixture() {
  const writes: Buffer[] = [], messages: string[] = [], failures: string[] = [];
  const transport = new CodexPipeTransport(value => writes.push(value), value => messages.push(value), value => failures.push(value));
  transport.start();
  const request = writes[0]!.toString();
  assert.ok(request.startsWith("GET / HTTP/1.1\r\n"));
  const key = /Sec-WebSocket-Key: (.+)\r\n/u.exec(request)![1]!;
  const accept = createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  const headers = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n";
  return {transport, writes, messages, failures, headers};
}

test("managed Codex IPC upgrades WebSocket before accepting JSON-RPC and handles split/coalesced bytes", async () => {
  const f = fixture();
  assert.throws(() => f.transport.send({id: 1}), /unavailable/);
  const wire = Buffer.concat([Buffer.from(f.headers), frame('{"id":1,"result":{}}'), frame('{"id":2,"result":{}}')]);
  for (const byte of wire.subarray(0, 23)) f.transport.receive(Buffer.from([byte]));
  f.transport.receive(wire.subarray(23));
  await f.transport.ready;
  assert.deepEqual(f.messages.map(value => JSON.parse(value).id), [1, 2]);
  assert.deepEqual(f.failures, []);
});

test("outgoing JSON-RPC uses masked UTF-8 frames at each RFC length boundary", async () => {
  const f = fixture(); f.transport.receive(Buffer.from(f.headers)); await f.transport.ready;
  for (const value of [{id: 1}, {text: "é".repeat(70)}, {text: "x".repeat(65536)}]) {
    f.transport.send(value);
    const decoded = clientFrame(f.writes.at(-1)!);
    assert.equal(decoded.opcode, 1);
    assert.deepEqual(JSON.parse(decoded.payload.toString()), value);
  }
  assert.deepEqual(f.failures, []);
});

test("a maximum-size message can finish beside a coalesced 32 KiB message in an ordinary pipe chunk", async () => {
  const f = fixture(); f.transport.receive(Buffer.from(f.headers)); await f.transport.ready;
  const largeText = JSON.stringify({text: "x".repeat(1024 * 1024 - 11)});
  const smallText = JSON.stringify({text: "y".repeat(32 * 1024 - 11)});
  assert.equal(Buffer.byteLength(largeText), 1024 * 1024);
  assert.equal(Buffer.byteLength(smallText), 32 * 1024);
  const large = frame(largeText), split = large.length - 100;
  for (let offset = 0; offset < split; offset += 65536) f.transport.receive(large.subarray(offset, Math.min(split, offset + 65536)));
  assert.deepEqual(f.messages, []);
  const coalesced = Buffer.concat([large.subarray(split), frame(smallText)]);
  assert.ok(coalesced.length < 65536);
  f.transport.receive(coalesced);
  assert.deepEqual(f.messages, [largeText, smallText]);
  assert.deepEqual(f.failures, []);
});

test("fragmented UTF-8 survives interleaved ping and returns a masked pong", async () => {
  const f = fixture(); f.transport.receive(Buffer.from(f.headers)); await f.transport.ready;
  const text = Buffer.from('{"result":"é🙂"}');
  const split = text.indexOf(Buffer.from("é")) + 1;
  f.transport.receive(frame(text.subarray(0, split), 1, false));
  f.transport.receive(frame("ping", 9));
  assert.deepEqual(f.messages, []);
  assert.deepEqual(clientFrame(f.writes.at(-1)!), {opcode: 10, payload: Buffer.from("ping")});
  const tail = frame(text.subarray(split), 0);
  for (let i = 0; i < tail.length; i++) f.transport.receive(tail.subarray(i, i + 1));
  assert.deepEqual(f.messages, [text.toString()]);
  assert.deepEqual(f.failures, []);
});

for (const name of ["redirect", "wrong-accept", "duplicate-header", "unsolicited-extension", "unsolicited-protocol", "oversized-header"] as const) {
  test(`WebSocket upgrade rejects ${name}`, async () => {
    const f = fixture();
    const headers = name === "redirect" ? f.headers.replace("101 Switching Protocols", "302 Found")
      : name === "wrong-accept" ? f.headers.replace(/Sec-WebSocket-Accept: [^\r]+/u, "Sec-WebSocket-Accept: incorrect")
      : name === "duplicate-header" ? f.headers.replace("\r\n\r\n", "\r\nUpgrade: websocket\r\n\r\n")
      : name === "unsolicited-extension" ? f.headers.replace("\r\n\r\n", "\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
      : name === "unsolicited-protocol" ? f.headers.replace("\r\n\r\n", "\r\nSec-WebSocket-Protocol: unexpected\r\n\r\n") : "x".repeat(16385);
    f.transport.receive(Buffer.from(headers));
    await assert.rejects(f.transport.ready);
    assert.deepEqual(f.failures, ["invalid"]);
    assert.deepEqual(f.messages, []);
  });
}

for (const [name, wire] of [
  ["masked server frame", Buffer.from([0x81, 0x80, 0, 0, 0, 0])],
  ["binary RPC", frame("value", 2)],
  ["unnegotiated RSV", Buffer.from([0xc1, 0])],
  ["orphan continuation", frame("value", 0)],
  ["fragmented control", frame("ping", 9, false)],
  ["invalid UTF-8", frame(Buffer.from([0xc3, 0x28]))],
  ["noncanonical length", Buffer.from([0x81, 126, 0, 1, 1])],
  ["oversized payload", Buffer.from([0x81, 127, 0, 0, 0, 0, 0, 16, 0, 1])],
  ["malformed close", frame(Buffer.from([0]), 8)],
  ["invalid close code", frame(Buffer.from([3, 237]), 8)],
] as const) test(`Codex IPC rejects ${name} before delivering content`, async () => {
  const f = fixture(); f.transport.receive(Buffer.from(f.headers)); await f.transport.ready;
  f.transport.receive(wire);
  assert.deepEqual(f.failures, ["invalid"]);
  assert.deepEqual(f.messages, []);
});

test("fragment accumulation is bounded before a second large payload is buffered", async () => {
  const f = fixture(); f.transport.receive(Buffer.from(f.headers)); await f.transport.ready;
  f.transport.receive(frame(Buffer.alloc(600000, 0x61), 1, false));
  const next = frame(Buffer.alloc(600000, 0x62), 0);
  f.transport.receive(next.subarray(0, 10));
  assert.deepEqual(f.failures, ["invalid"]);
  assert.deepEqual(f.messages, []);
});

for (const payload of ["", "x"]) test(`fragment count bounds ${payload === "" ? "empty" : "tiny"} continuations independently of payload bytes`, async () => {
  const f = fixture(); f.transport.receive(Buffer.from(f.headers)); await f.transport.ready;
  f.transport.receive(frame("x", 1, false));
  f.transport.receive(Buffer.concat(Array.from({length: 4095}, () => frame(payload, 0, false))));
  assert.deepEqual(f.failures, []);
  f.transport.receive(frame(payload, 0, false));
  assert.deepEqual(f.failures, ["invalid"]);
  assert.deepEqual(f.messages, []);
  assert.throws(() => f.transport.send({id: 1}), /unavailable/);
});

test("the last allowed fragment completes a message and resets the fragment budget", async () => {
  const f = fixture(); f.transport.receive(Buffer.from(f.headers)); await f.transport.ready;
  f.transport.receive(frame("x", 1, false));
  f.transport.receive(Buffer.concat(Array.from({length: 4094}, () => frame("x", 0, false))));
  f.transport.receive(frame("x", 0));
  f.transport.receive(frame("next"));
  assert.deepEqual(f.messages, ["x".repeat(4096), "next"]);
  assert.deepEqual(f.failures, []);
});

test("normal close is acknowledged without treating it as JSON-RPC", async () => {
  const f = fixture(); f.transport.receive(Buffer.from(f.headers)); await f.transport.ready;
  f.transport.receive(frame(Buffer.from([3, 232]), 8));
  assert.deepEqual(f.failures, ["closed"]);
  assert.deepEqual(clientFrame(f.writes.at(-1)!), {opcode: 8, payload: Buffer.from([3, 232])});
  assert.deepEqual(f.messages, []);
});

test("closing a stalled handshake settles readiness and discards future data", async () => {
  const f = fixture(); f.transport.close(); f.transport.receive(Buffer.from(f.headers));
  await assert.rejects(f.transport.ready);
  assert.deepEqual(f.messages, []);
});
