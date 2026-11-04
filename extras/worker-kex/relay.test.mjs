import test from 'node:test';
import assert from 'node:assert/strict';
import tls from 'node:tls';
import { createWorker, encodeRequest, decodeResponse, MAX_PAYLOAD } from './relay.mjs';

const clientToken = '11'.repeat(32);
const upstreamToken = '22'.repeat(32);
const env = { CLIENT_TOKEN: clientToken, UPSTREAM_TOKEN: upstreamToken, UPSTREAM_HOST: 'upstream.test', UPSTREAM_PORT: '8443', TIMEOUT_MS: '300' };
const payload = new TextEncoder().encode('hello');
function request(body = payload, options = {}) {
  return new Request('https://relay.test/k', { method: 'POST', headers: { authorization: `Bearer ${clientToken}` }, body, duplex: 'half', ...options });
}
function frame(body = payload, status = 0) {
  const result = new Uint8Array(12 + body.length);
  result.set([75, 88, 82, 70, 1, 2, status, 0]);
  new DataView(result.buffer).setUint32(8, body.length);
  result.set(body, 12);
  return result;
}

// 模拟 runtime Socket，可记录写入、关闭与取消，并注入每个阻塞阶段。
function fake({ chunks = [frame()], hang, writeError, openError } = {}) {
  const state = { calls: 0, closes: 0, writes: [], canceled: 0 };
  let readController;
  const connect = (address, options) => {
    state.calls++;
    assert.deepEqual(address, { hostname: 'upstream.test', port: 8443 });
    assert.deepEqual(options, { secureTransport: 'on' });
    let unblock;
    const blocked = new Promise((resolve) => { unblock = resolve; });
    return {
      opened: openError ? Promise.reject(new Error('secret upstream cert')) : hang === 'open' ? blocked : Promise.resolve({}),
      closed: openError ? Promise.reject(new Error('secret socket closed')) : Promise.resolve(),
      readable: new ReadableStream({
        start(controller) {
          readController = controller;
          for (const chunk of chunks) controller.enqueue(chunk);
          if (hang !== 'read') controller.close();
        },
        cancel() { state.canceled++; },
      }),
      writable: new WritableStream({
        write(bytes) { state.writes.push(bytes.slice()); if (writeError) throw new Error('secret write'); if (hang === 'write') return blocked; },
      }),
      close() { state.closes++; unblock(); try { readController.error(new Error('closed')); } catch {} return Promise.resolve(); },
    };
  };
  return { state, worker: createWorker(connect) };
}

async function expectError(response, status) {
  assert.equal(response.status, status);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const body = await response.text();
  assert(!body.includes('secret'));
  assert(!body.includes(clientToken));
  assert(!body.includes(upstreamToken));
}

test('分片响应、固定目标与独立上游凭据', async () => {
  const encoded = frame();
  const { worker, state } = fake({ chunks: [encoded.slice(0, 3), encoded.slice(3, 13), encoded.slice(13)] });
  const result = await worker.fetch(request(), env);
  assert.equal(result.status, 200);
  assert.equal(await result.text(), 'hello');
  assert.equal(state.calls, 1);
  assert.equal(state.closes, 1);
  assert.equal(state.writes.length, 1);
  assert.deepEqual(state.writes[0], encodeRequest(new Uint8Array(32).fill(0x22), payload));
});

test('16 KiB 请求与响应边界', async () => {
  const body = new Uint8Array(MAX_PAYLOAD).fill(7);
  const { worker, state } = fake({ chunks: [frame(body)] });
  const result = await worker.fetch(request(body), env);
  assert.equal(result.status, 200);
  assert.deepEqual(new Uint8Array(await result.arrayBuffer()), body);
  assert.equal(state.writes[0].length, MAX_PAYLOAD + 44);
});

test('路由与鉴权失败不建立连接', async () => {
  for (const [req, status] of [
    [new Request('https://relay.test/other'), 404],
    [new Request('https://relay.test/k'), 405],
    [request(payload, { headers: {} }), 401],
    [request(payload, { headers: { authorization: `Bearer ${upstreamToken}` } }), 401],
    [request(payload, { headers: { authorization: 'Bearer short-secret' } }), 401],
  ]) {
    const { worker, state } = fake();
    await expectError(await worker.fetch(req, env), status);
    assert.equal(state.calls, 0);
  }
});

test('无效配置和相同凭据关闭入口', async () => {
  for (const change of [
    { UPSTREAM_TOKEN: clientToken }, { UPSTREAM_TOKEN: 'short-secret' },
    { UPSTREAM_HOST: '127.0.0.1' }, { UPSTREAM_HOST: '[::1]' }, { UPSTREAM_HOST: 'evil/path' },
    { UPSTREAM_HOST: 'localhost' }, { UPSTREAM_HOST: 'a.localhost' },
    { UPSTREAM_PORT: '0' }, { UPSTREAM_PORT: '65536' }, { UPSTREAM_PORT: '443junk' },
    { TIMEOUT_MS: '-1' }, { TIMEOUT_MS: '30001' },
  ]) {
    const { worker, state } = fake();
    await expectError(await worker.fetch(request(), { ...env, ...change }), 500);
    assert.equal(state.calls, 0);
  }
});

test('流式体长限制不信任 Content-Length，拒绝时取消上传', async () => {
  for (const declared of [undefined, '1', String(MAX_PAYLOAD + 1)]) {
    let canceled = false;
    const body = new ReadableStream({
      start(c) { c.enqueue(new Uint8Array(MAX_PAYLOAD)); c.enqueue(new Uint8Array(1)); },
      cancel() { canceled = true; },
    });
    const headers = { authorization: `Bearer ${clientToken}` };
    if (declared) headers['content-length'] = declared;
    const { worker, state } = fake();
    await expectError(await worker.fetch(request(body, { headers }), env), 413);
    assert(canceled);
    assert.equal(state.calls, 0);
  }
});

test('空体拒绝且不拨号', async () => {
  for (const body of [undefined, new Uint8Array()]) {
    const { worker, state } = fake();
    const req = new Request('https://relay.test/k', { method: 'POST', headers: { authorization: `Bearer ${clientToken}` }, body });
    await expectError(await worker.fetch(req, env), 400);
    assert.equal(state.calls, 0);
  }
});

test('上传阻塞超时并取消读取', async () => {
  let canceled = false;
  const body = new ReadableStream({ cancel() { canceled = true; } });
  const { worker, state } = fake();
  await expectError(await worker.fetch(request(body), { ...env, TIMEOUT_MS: '25' }), 504);
  assert(canceled);
  assert.equal(state.calls, 0);
});

test('连接、写入、响应 EOF 阻塞均超时且只关闭一次', async () => {
  for (const hang of ['open', 'write', 'read']) {
    const { worker, state } = fake({ hang });
    await expectError(await worker.fetch(request(), { ...env, TIMEOUT_MS: '25' }), 504);
    assert.equal(state.calls, 1);
    assert.equal(state.closes, 1);
  }
});

test('客户端取消覆盖上传与所有上游阶段', async () => {
  for (const stage of ['upload', 'open', 'write', 'read']) {
    const controller = new AbortController();
    let canceled = false;
    const body = stage === 'upload' ? new ReadableStream({ cancel() { canceled = true; } }) : payload;
    const { worker, state } = fake({ hang: stage });
    const pending = worker.fetch(request(body, { signal: controller.signal }), env);
    const timer = setTimeout(() => controller.abort(), 10);
    await expectError(await pending, 408);
    clearTimeout(timer);
    assert.equal(state.calls, stage === 'upload' ? 0 : 1);
    assert.equal(state.closes, stage === 'upload' ? 0 : 1);
    if (stage === 'upload') assert(canceled);
  }
  const controller = new AbortController(); controller.abort();
  const { worker, state } = fake();
  await expectError(await worker.fetch(request(payload, { signal: controller.signal }), env), 408);
  assert.equal(state.calls, 0);
});

test('TLS 连接和写入错误不重试、不泄漏', async () => {
  for (const options of [{ openError: true }, { writeError: true }]) {
    const { worker, state } = fake(options);
    await expectError(await worker.fetch(request(), env), 502);
    assert.equal(state.calls, 1);
    assert.equal(state.closes, 1);
  }
  const worker = createWorker(() => { throw new Error('secret connect'); });
  await expectError(await worker.fetch(request(), env), 502);
});

test('拒绝坏版本、非法长度、截断及多响应', async () => {
  const mutations = [
    (b) => { b[0] = 0; return b; }, (b) => { b[4] = 2; return b; },
    (b) => { b[5] = 1; return b; }, (b) => { b[6] = 255; return b; },
    (b) => { b[7] = 1; return b; }, (b) => { new DataView(b.buffer).setUint32(8, MAX_PAYLOAD + 1); return b; },
    (b) => b.slice(0, 10), (b) => b.slice(0, -1),
    (b) => new Uint8Array([...b, ...b]), () => new Uint8Array(MAX_PAYLOAD + 13),
    () => frame(new Uint8Array()), (b) => { b[6] = 1; return b; },
  ];
  for (const mutate of mutations) {
    const { worker, state } = fake({ chunks: [mutate(frame())] });
    await expectError(await worker.fetch(request(), env), 502);
    assert.equal(state.calls, 1);
    assert.equal(state.closes, 1);
  }
});

test('固定远端错误码不暴露凭据错误给客户端', async () => {
  for (const status of [1, 2, 3, 4]) {
    const { worker } = fake({ chunks: [frame(new Uint8Array(), status)] });
    await expectError(await worker.fetch(request(), env), status === 4 ? 504 : 502);
  }
});

test('响应解析支持带偏移的 Uint8Array', () => {
  const b = frame();
  const big = new Uint8Array(b.length + 10); big.set(b, 5);
  assert.deepEqual(decodeResponse(big.subarray(5, 5 + b.length)), payload);
});

// Go 集成测试提供回环地址和临时 CA；生产目标仍只来自固定配置。
test('与 Go TLS 服务互通且关闭连接', { skip: !process.env.KEXRELAY_TEST_ADDR }, async () => {
  const [host, port] = process.env.KEXRELAY_TEST_ADDR.split(':');
  let connections = 0, closes = 0;
  const worker = createWorker((address, options) => {
    assert.deepEqual(address, { hostname: 'upstream.test', port: 8443 });
    assert.equal(options.secureTransport, 'on');
    connections++;
    const socket = tls.connect({ host, port: Number(port), servername: address.hostname, ca: process.env.KEXRELAY_TEST_CA, rejectUnauthorized: true });
    const opened = new Promise((resolve, reject) => { socket.once('secureConnect', resolve); socket.once('error', reject); });
    const closed = new Promise((resolve) => socket.once('close', resolve));
    // 显式适配 TLS 流，避免测试运行时 Duplex.toWeb 在握手期间的暂停状态。
    const streams = {
      readable: new ReadableStream({
        start(controller) {
          socket.on('data', (bytes) => controller.enqueue(new Uint8Array(bytes)));
          socket.once('end', () => controller.close());
          socket.once('error', (error) => controller.error(error));
        },
        cancel() { socket.destroy(); },
      }),
      writable: new WritableStream({
        write(bytes) { return new Promise((resolve, reject) => socket.write(bytes, (error) => error ? reject(error) : resolve())); },
        abort() { socket.destroy(); },
      }),
    };
    return { ...streams, opened, closed, close() { closes++; socket.destroy(); return closed; } };
  });
  for (const body of [payload, new Uint8Array(MAX_PAYLOAD).fill(0x5a)]) {
    const result = await worker.fetch(request(body), { ...env, TIMEOUT_MS: '3000' });
    assert.equal(result.status, 200);
    assert.deepEqual(new Uint8Array(await result.arrayBuffer()), body);
  }
  assert.equal(connections, 2);
  assert.equal(closes, 2);
});



test('只发送非法响应头时立即拒绝，不等待 EOF', async () => {
  const header = frame().slice(0, 12);
  new DataView(header.buffer).setUint32(8, MAX_PAYLOAD + 1);
  const { worker, state } = fake({ chunks: [header], hang: 'read' });
  await expectError(await worker.fetch(request(), env), 502);
  assert.equal(state.closes, 1);
});
