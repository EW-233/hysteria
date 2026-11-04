import test from "node:test";
import assert from "node:assert/strict";
import { relay, LIMITS, default as worker } from "./index.mjs";
import { setImmediate as tick } from "node:timers/promises";

// 模拟 Worker 原生 WebSocket 与 TCP Streams，覆盖边界、限额和关闭清理。
function harness(limits = {}) {
  const ws = new EventTarget(); ws.sent = []; ws.closed = null;
  ws.send = b => ws.sent.push(new Uint8Array(b));
  ws.close = (code, reason) => { ws.closed = { code, reason }; };
  ws.message = b => ws.dispatchEvent(Object.assign(new Event("message"), { data: b }));
  let source; const writes = []; let socketClosed = false;
  const socket = {
    readable: new ReadableStream({ start(c) { source = c; } }),
    writable: new WritableStream({ write(b) { writes.push(b); } }),
    close() { socketClosed = true; },
  };
  const session = relay(ws, socket, { ...LIMITS, ...limits });
  return { ws, writes, source, session, get closed() { return socketClosed; } };
}

test("双向帧的拆包、粘包和写序列", async () => {
  const h = harness();
  h.ws.message(new Uint8Array([1, 2, 3]).buffer);
  h.ws.message(new Uint8Array([4]).buffer);
  await tick();
  assert.deepEqual(h.writes.map(b => [...b]), [[0, 3, 1, 2, 3], [0, 1, 4]]);
  for (const b of [[0], [3, 8], [9, 10, 0, 1, 11]]) h.source.enqueue(new Uint8Array(b));
  await tick();
  assert.deepEqual(h.ws.sent.map(b => [...b]), [[8, 9, 10], [11]]);
  h.session.close(); await h.session.done;
  assert.equal(h.closed, true);
});
test("拒绝文本、空包、超限及非法后端帧", async () => {
  for (const b of ["text", new ArrayBuffer(0), new ArrayBuffer(2049)]) {
    const h = harness(); h.ws.message(b); await h.session.done;
    assert.equal(h.ws.closed.code, 1008); assert.equal(h.writes.length, 0);
  }
  const h = harness(); h.source.enqueue(new Uint8Array([0, 0])); await h.session.done;
  assert.equal(h.ws.closed.code, 1008);
});
test("累计字节、队列与生命周期受限", async () => {
  for (const limits of [{ bytes: 2 }, { queue: 3 }]) {
    const h = harness(limits); h.ws.message(new ArrayBuffer(3)); await h.session.done;
    assert.equal(h.ws.closed.code, 1008);
  }
  const h = harness({ lifetime: 10 }); await h.session.done;
  assert.equal(h.ws.closed.reason, "lifetime limit");
  const idle = harness({ idle: 10 }); await idle.session.done;
  assert.equal(idle.ws.closed.reason, "idle limit");
});
test("未认证不得创建后端，路径与升级请求严格检查", async () => {
  let connected = 0;
  const env = { HDM_TOKEN: "secret", HDM_VPC: { connect() { connected++; throw new Error(); } } };
  const request = (path, headers = {}) => worker.fetch(new Request("https://example.com" + path, { headers }), env);
  assert.equal((await request("/hdm/connect")).status, 401);
  assert.equal((await request("/hdm/connect?target=evil")).status, 404);
  assert.equal((await request("/health")).status, 200);
  assert.equal((await request("/hdm/connect", { Authorization: "Bearer secret" })).status, 426);
  assert.equal(connected, 0);
  assert.equal((await request("/hdm/connect", { Authorization: "Bearer secret", Upgrade: "websocket" })).status, 502);
  assert.equal(connected, 1);
});

// 原生平台默认 Blob：模拟升级链路，确保接收前已改为 ArrayBuffer。
test("升级之前固定二进制类型和回环后端", async () => {
  const SavedPair = globalThis.WebSocketPair;
  const SavedResponse = globalThis.Response;
  let accepted = false, backend;
  const ws = new EventTarget(); ws.binaryType = "blob";
  ws.accept = () => { assert.equal(ws.binaryType, "arraybuffer"); accepted = true; };
  ws.send = () => {}; ws.close = () => {};
  let control;
  const socket = { readable: new ReadableStream({ start(c) { control = c; } }), writable: new WritableStream(), close() {} };
  try {
    globalThis.WebSocketPair = class { constructor() { this[0] = {}; this[1] = ws; } };
    globalThis.Response = class { constructor(body, init) { this.status = init.status; this.webSocket = init.webSocket; } };
    const response = await worker.fetch(new Request("https://example.com/hdm/connect", { headers: { Authorization: "Bearer test-token", Upgrade: "websocket" } }), {
      HDM_TOKEN: "test-token", HDM_VPC: { connect(target) { backend = target; return socket; } }
    });
    assert.equal(response.status, 101); assert.equal(accepted, true);
    assert.equal(backend, "127.0.0.1:18080");
  } finally {
    ws.dispatchEvent(new Event("close"));
    globalThis.WebSocketPair = SavedPair; globalThis.Response = SavedResponse;
    await tick();
  }
});
