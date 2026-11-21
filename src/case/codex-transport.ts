import { createHash, randomBytes } from "node:crypto";

const LIMIT = 1024 * 1024;
const HEADER_LIMIT = 16 * 1024;
const FRAGMENT_LIMIT = 4096;
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
type Failure = "closed" | "invalid";

/** The managed Unix socket speaks WebSocket; `app-server proxy` copies bytes.
 * This codec owns only subprocess pipes, with no TCP or HTTP client capability. */
export class CodexPipeTransport {
  readonly ready: Promise<void>;
  private readonly key = randomBytes(16).toString("base64");
  private readonly accept = createHash("sha1").update(this.key + GUID).digest("base64");
  private resolve!: () => void;
  private reject!: (error: Error) => void;
  private buffer: Buffer = Buffer.alloc(0);
  private fragments: Buffer[] = [];
  private fragmented = false;
  private fragmentBytes = 0;
  private fragmentCount = 0;
  private upgraded = false;
  private closed = false;

  constructor(private readonly write: (bytes: Buffer) => void,
    private readonly message: (text: string) => void, private readonly failure: (kind: Failure) => void) {
    this.ready = new Promise<void>((resolve, reject) => { this.resolve = resolve; this.reject = reject; });
    void this.ready.catch(() => undefined);
  }

  start(): void {
    this.write(Buffer.from("GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
      + `Sec-WebSocket-Key: ${this.key}\r\nSec-WebSocket-Version: 13\r\n\r\n`, "ascii"));
  }

  send(value: unknown): void {
    if (!this.upgraded || this.closed) throw new Error("Codex pipe transport unavailable");
    const payload = Buffer.from(JSON.stringify(value), "utf8");
    if (payload.length > LIMIT) throw new Error("Codex pipe message exceeds its limit");
    this.frame(1, payload);
  }

  receive(bytes: Uint8Array): void {
    if (this.closed) return;
    try {
      // Pipe chunks can finish one maximum-sized message and contain another.
      // Bound retained incomplete data, while consuming complete frames between
      // small appends instead of rejecting valid coalesced messages wholesale.
      let consumed = 0;
      do {
        const end = Math.min(bytes.byteLength, consumed + HEADER_LIMIT);
        this.buffer = Buffer.concat([this.buffer, bytes.subarray(consumed, end)]);
        consumed = end;
        if (!this.upgraded && !this.handshake()) continue;
        while (!this.closed && this.readFrame()) { /* Consume complete frames only. */ }
        if (this.buffer.length > LIMIT + 14) throw new Error();
      } while (!this.closed && consumed < bytes.byteLength);
    } catch { this.fail("invalid"); }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.buffer = Buffer.alloc(0); this.fragments = []; this.fragmentBytes = 0; this.fragmentCount = 0;
    this.reject(new Error("Codex pipe transport closed"));
  }

  private fail(kind: Failure): void {
    if (this.closed) return;
    this.close(); this.failure(kind);
  }

  private handshake(): boolean {
    const end = this.buffer.indexOf("\r\n\r\n");
    if (end < 0) { if (this.buffer.length > HEADER_LIMIT) throw new Error(); return false; }
    if (end > HEADER_LIMIT || this.buffer.subarray(0, end).some(byte => byte > 127)) throw new Error();
    const lines = this.buffer.subarray(0, end).toString("ascii").split("\r\n");
    if (!/^HTTP\/1\.1 101(?: |$)/u.test(lines.shift() ?? "")) throw new Error();
    const headers = new Map<string, string>();
    for (const line of lines) {
      const index = line.indexOf(":");
      const name = line.slice(0, index).toLowerCase();
      if (index < 1 || !/^[a-z0-9!#$%&'*+.^_`|~-]+$/u.test(name) || headers.has(name)) throw new Error();
      headers.set(name, line.slice(index + 1).trim());
    }
    if (headers.get("upgrade")?.toLowerCase() !== "websocket"
      || !headers.get("connection")?.toLowerCase().split(",").map(value => value.trim()).includes("upgrade")
      || headers.get("sec-websocket-accept") !== this.accept
      || headers.has("sec-websocket-extensions") || headers.has("sec-websocket-protocol") || headers.has("transfer-encoding")) throw new Error();
    this.buffer = this.buffer.subarray(end + 4);
    this.upgraded = true; this.resolve();
    return true;
  }

  private frame(opcode: number, payload: Buffer): void {
    const extra = payload.length < 126 ? 0 : payload.length <= 65535 ? 2 : 8;
    const result = Buffer.allocUnsafe(2 + extra + 4 + payload.length);
    result[0] = 0x80 | opcode;
    result[1] = 0x80 | (extra === 0 ? payload.length : extra === 2 ? 126 : 127);
    if (extra === 2) result.writeUInt16BE(payload.length, 2);
    else if (extra === 8) result.writeBigUInt64BE(BigInt(payload.length), 2);
    const mask = randomBytes(4);
    mask.copy(result, 2 + extra);
    for (let i = 0; i < payload.length; i++) result[6 + extra + i] = payload[i]! ^ mask[i % 4]!;
    this.write(result);
  }

  private readFrame(): boolean {
    if (this.buffer.length < 2) return false;
    const first = this.buffer[0]!, second = this.buffer[1]!;
    const final = (first & 0x80) !== 0, opcode = first & 15;
    if ((first & 0x70) !== 0 || (second & 0x80) !== 0 || ![0, 1, 8, 9, 10].includes(opcode)) throw new Error();
    const control = opcode >= 8;
    let length = second & 127, offset = 2;
    if (control && (!final || length > 125)) throw new Error();
    if (length === 126) {
      if (this.buffer.length < 4) return false;
      length = this.buffer.readUInt16BE(2); offset = 4;
      if (length < 126) throw new Error();
    } else if (length === 127) {
      if (this.buffer.length < 10) return false;
      const size = this.buffer.readBigUInt64BE(2);
      if (size < 65536n || size > BigInt(LIMIT)) throw new Error();
      length = Number(size); offset = 10;
    }
    if (length > LIMIT || (!control && this.fragmentBytes + length > LIMIT)) throw new Error();
    if (!control && ((opcode === 1 && this.fragmented) || (opcode === 0 && !this.fragmented))) throw new Error();
    // A byte limit alone permits unlimited empty continuation Buffer objects.
    if (opcode === 0 && this.fragmentCount >= FRAGMENT_LIMIT) throw new Error();
    if (this.buffer.length < offset + length) return false;
    const payload = Buffer.from(this.buffer.subarray(offset, offset + length));
    this.buffer = this.buffer.subarray(offset + length);
    if (opcode === 9) { this.frame(10, payload); return true; }
    if (opcode === 10) return true;
    if (opcode === 8) {
      if (payload.length === 1) throw new Error();
      if (payload.length >= 2) {
        const code = payload.readUInt16BE(0);
        if (!(code >= 1000 && code <= 1014 && ![1004, 1005, 1006].includes(code)) && !(code >= 3000 && code <= 4999)) throw new Error();
        new TextDecoder("utf-8", {fatal: true}).decode(payload.subarray(2));
      }
      this.frame(8, payload); this.fail("closed"); return false;
    }
    if (opcode === 1) {
      if (final) this.message(new TextDecoder("utf-8", {fatal: true}).decode(payload));
      else { this.fragmented = true; this.fragments = [payload]; this.fragmentBytes = length; this.fragmentCount = 1; }
    } else {
      this.fragments.push(payload); this.fragmentBytes += length; this.fragmentCount++;
      if (final) {
        const value = Buffer.concat(this.fragments, this.fragmentBytes);
        this.fragments = []; this.fragmentBytes = 0; this.fragmentCount = 0; this.fragmented = false;
        this.message(new TextDecoder("utf-8", {fatal: true}).decode(value));
      }
    }
    return true;
  }
}
