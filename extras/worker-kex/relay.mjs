// 协议与请求生命周期独立于 Worker 入口，便于使用真实 TLS 适配器验证。
export const MAX_PAYLOAD = 16 * 1024;
export const HEADER_SIZE = 12;
export const CREDENTIAL_SIZE = 32;
const encoder = new TextEncoder();

class Failure extends Error {
  constructor(status) { super('relay failed'); this.status = status; }
}

function credential(value) {
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) throw new Failure(500);
  return Uint8Array.from(value.match(/../g), (byte) => parseInt(byte, 16));
}

// 仅用于检查两份部署配置是否相同，不用于外部输入的凭据鉴权。
function equal(a, b) {
  let diff = a.length ^ b.length;
  for (let i = 0; i < CREDENTIAL_SIZE; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// 使用原生 WebCrypto 验证 HMAC，由加密实现比较标签，避免 JS/JIT 比较秘密。
// 固定公开 HMAC key 仅用于构造等长比较标签，不是部署凭据或认证密钥。
async function authenticate(expected, supplied) {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  const tag = await crypto.subtle.sign('HMAC', key, expected);
  return crypto.subtle.verify('HMAC', key, tag, supplied);
}

function config(env) {
  const client = credential(env.CLIENT_TOKEN);
  const upstream = credential(env.UPSTREAM_TOKEN);
  const hostname = env.UPSTREAM_HOST;
  const portText = String(env.UPSTREAM_PORT ?? '');
  const port = Number(portText);
  const timeoutText = String(env.TIMEOUT_MS ?? '5000');
  const timeout = Number(timeoutText);
  // 仅允许部署配置中的完整 DNS 主机名；HTTP 输入不能改变目标。
  if (equal(client, upstream) || typeof hostname !== 'string' || hostname.length > 253 ||
      !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(hostname) ||
      hostname.toLowerCase().endsWith('.localhost') ||
      !/^\d+$/.test(portText) || !Number.isInteger(port) || port < 1 || port > 65535 ||
      !/^\d+$/.test(timeoutText) || !Number.isInteger(timeout) || timeout < 1 || timeout > 30000) {
    throw new Failure(500);
  }
  return { client, upstream, hostname, port, timeout };
}

function response(status, payload) {
  return new Response(payload ?? (status === 401 ? 'Unauthorized' : 'Request failed'), {
    status,
    headers: { 'content-type': payload ? 'application/octet-stream' : 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
  });
}

// 同一个绝对截止时间覆盖上传、连接、写入、读取及 EOF，取消不会重新拨号。
function lifetime(signal, timeout) {
  let rejectAbort;
  const aborted = new Promise((_, reject) => { rejectAbort = reject; });
  // 取消可能发生在第一个异步操作之前，预先安装拒绝处理。
  aborted.catch(() => {});
  const abort = () => rejectAbort(new Failure(408));
  const timer = setTimeout(() => rejectAbort(new Failure(504)), timeout);
  signal.addEventListener('abort', abort, { once: true });
  if (signal.aborted) abort();
  return {
    wait: (promise) => Promise.race([promise, aborted]),
    dispose: () => { clearTimeout(timer); signal.removeEventListener('abort', abort); },
  };
}

function ignore(action) {
  try { Promise.resolve(action()).catch(() => {}); } catch { /* 清理失败不能暴露运行时错误。 */ }
}

// 每次读取后先检查总长度，再写入固定容量缓冲，不依赖可能伪造的 Content-Length。
async function readBounded(reader, limit, life, tooLarge, inspect) {
  const buffer = new Uint8Array(limit);
  let length = 0;
  for (;;) {
    const { done, value } = await life.wait(reader.read());
    if (done) break;
    if (!(value instanceof Uint8Array)) throw new Failure(502);
    if (value.byteLength > limit - length) throw new Failure(tooLarge);
    buffer.set(value, length);
    length += value.byteLength;
    if (inspect) inspect(buffer.subarray(0, length));
  }
  return buffer.slice(0, length);
}

export function encodeRequest(token, payload) {
  if (token.length !== CREDENTIAL_SIZE || payload.length < 1 || payload.length > MAX_PAYLOAD) throw new Failure(400);
  const frame = new Uint8Array(HEADER_SIZE + CREDENTIAL_SIZE + payload.length);
  frame.set(encoder.encode('KXRF'));
  frame[4] = 1;
  frame[5] = 1;
  new DataView(frame.buffer).setUint32(8, payload.length, false);
  frame.set(token, HEADER_SIZE);
  frame.set(payload, HEADER_SIZE + CREDENTIAL_SIZE);
  return frame;
}

// 头部到齐后立即拒绝非法声明；不等待恶意上游补齐或结束超长帧。
function responseLength(frame) {
  if (frame.length < HEADER_SIZE || frame[0] !== 75 || frame[1] !== 88 || frame[2] !== 82 || frame[3] !== 70 ||
      frame[4] !== 1 || frame[5] !== 2 || frame[7] !== 0 || frame[6] > 4) throw new Failure(502);
  const length = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(8, false);
  if (length > MAX_PAYLOAD || (frame[6] === 0 && length === 0) || (frame[6] !== 0 && length !== 0)) throw new Failure(502);
  return HEADER_SIZE + length;
}

function inspectResponse(frame) {
  if (frame.length >= HEADER_SIZE && frame.length > responseLength(frame)) throw new Failure(502);
}

export function decodeResponse(frame) {
  if (frame.length !== responseLength(frame)) throw new Failure(502);
  if (frame[6] !== 0) throw new Failure(frame[6] === 4 ? 504 : 502);
  return frame.slice(HEADER_SIZE);
}
// connect 由 Worker 入口注入；生产路径只使用 cloudflare:sockets 的 TLS 连接。
export function createWorker(connect) {
  return {
    async fetch(request, env) {
      let life, bodyReader, socket, upstreamReader, writer;
      try {
        const url = new URL(request.url);
        if (url.pathname !== '/k') return response(404);
        if (request.method !== 'POST') return response(405);
        const cfg = config(env);
        const auth = request.headers.get('authorization');
        if (!auth || !/^Bearer [0-9a-fA-F]{64}$/.test(auth)) return response(401);
        if (request.signal.aborted) throw new Failure(408);
        life = lifetime(request.signal, cfg.timeout);
        if (!await life.wait(authenticate(cfg.client, credential(auth.slice(7))))) return response(401);
        const declared = request.headers.get('content-length');
        if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_PAYLOAD)) throw new Failure(413);
        if (!request.body) throw new Failure(400);
        bodyReader = request.body.getReader();
        const payload = await readBounded(bodyReader, MAX_PAYLOAD, life, 413);
        if (payload.length === 0) throw new Failure(400);
        if (request.signal.aborted) throw new Failure(408);
        socket = connect({ hostname: cfg.hostname, port: cfg.port }, { secureTransport: 'on' });
        // closed/opened 的失败均被观察，避免取消期间出现未处理拒绝。
        Promise.resolve(socket.closed).catch(() => {});
        await life.wait(socket.opened);
        writer = socket.writable.getWriter();
        await life.wait(writer.write(encodeRequest(cfg.upstream, payload)));
        // 不提前关闭 writable：默认半关闭策略可能同时关闭 readable。
        upstreamReader = socket.readable.getReader();
        const frame = await readBounded(upstreamReader, HEADER_SIZE + MAX_PAYLOAD, life, 502, inspectResponse);
        return response(200, decodeResponse(frame));
      } catch (error) {
        return response(error instanceof Failure ? error.status : 502);
      } finally {
        life?.dispose();
        // 即使上传或 socket 卡住，清理也不能无限阻塞 HTTP 返回。
        if (socket) ignore(() => socket.close());
        if (bodyReader) { ignore(() => bodyReader.cancel()); ignore(() => bodyReader.releaseLock()); }
        else if (request.body) ignore(() => request.body.cancel());
        if (upstreamReader) { ignore(() => upstreamReader.cancel()); ignore(() => upstreamReader.releaseLock()); }
        if (writer) { ignore(() => writer.abort()); ignore(() => writer.releaseLock()); }
      }
    },
  };
}



