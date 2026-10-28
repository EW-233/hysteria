// 固定后端的握手中继：不解密内部 QUIC/TLS，限制每会话流量、排队和存活时间。
export const LIMITS = Object.freeze({ packet: 2048, bytes: 1048576, queue: 65536, lifetime: 15000, idle: 5000 });
const BACKEND = "127.0.0.1:18080";

export function relay(ws, socket, limits = LIMITS) {
  const reader = socket.readable.getReader();
  const writer = socket.writable.getWriter();
  let closed = false, total = 0, queued = 0, chain = Promise.resolve();
  let idle;
  const finish = (code = 1000, reason = "relay closed") => {
    if (closed) return;
    closed = true;
    clearTimeout(life); clearTimeout(idle);
    try { ws.close(code, reason); } catch {}
    void reader.cancel().catch(() => {});
    void writer.abort().catch(() => {});
    try { void Promise.resolve(socket.close()).catch(() => {}); } catch {}
  };
  const life = setTimeout(() => finish(1008, "lifetime limit"), limits.lifetime);
  const touch = () => { clearTimeout(idle); idle = setTimeout(() => finish(1008, "idle limit"), limits.idle); };
  const charge = n => {
    if (total + n > limits.bytes) { finish(1008, "byte limit"); return false; }
    total += n; touch(); return true;
  };
  touch();
  ws.addEventListener("close", () => finish());
  ws.addEventListener("error", () => finish(1011, "websocket error"));
  ws.addEventListener("message", event => {
    if (closed) return;
    if (!(event.data instanceof ArrayBuffer) || event.data.byteLength < 1 || event.data.byteLength > limits.packet) {
      finish(1008, "binary datagram required"); return;
    }
    const n = event.data.byteLength;
    if (queued + n + 2 > limits.queue) { finish(1008, "queue limit"); return; }
    if (!charge(n)) return;
    const frame = new Uint8Array(n + 2);
    frame[0] = n >>> 8; frame[1] = n & 255;
    frame.set(new Uint8Array(event.data), 2);
    queued += frame.length;
    // WritableStream 只允许一个写者；有界队列避免慢后端无限积压。
    chain = chain.then(async () => {
      if (!closed) await writer.write(frame);
    }).catch(() => finish(1011, "backend write failed")).finally(() => { queued -= frame.length; });
  });
  // 增量拆分 TCP 长度帧，正确处理拆包和粘包；最多缓存一个数据报。
  const pump = (async () => {
    const packet = new Uint8Array(limits.packet);
    let size = 0, header = 0, used = 0;
    try {
      while (!closed) {
        const { value, done } = await reader.read();
        if (done) { finish(used || header ? 1011 : 1000, "backend closed"); break; }
        for (let offset = 0; offset < value.length && !closed;) {
          if (header < 2) {
            size = (size << 8) | value[offset++]; header++;
            if (header < 2) continue;
            if (size < 1 || size > limits.packet) { finish(1008, "invalid backend frame"); break; }
          }
          const n = Math.min(size - used, value.length - offset);
          packet.set(value.subarray(offset, offset + n), used); offset += n; used += n;
          if (used === size) {
            if (!charge(size)) break;
            ws.send(packet.slice(0, size));
            size = 0; header = 0; used = 0;
          }
        }
      }
    } catch { finish(1011, "backend read failed"); }
  })();
  return { done: pump, close: finish };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") return new Response("ok");
    if (request.method !== "GET" || url.pathname !== "/hdm/connect" || url.search) return new Response("not found", { status: 404 });
    if (!env.HDM_TOKEN || request.headers.get("Authorization") !== `Bearer ${env.HDM_TOKEN}`) return new Response("unauthorized", { status: 401 });
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("websocket required", { status: 426 });
    let socket, expired = false, timer;
    try {
      // connect 超时后到达的 socket 仍须关闭，不能成为悬挂的后台连接。
      const opening = Promise.resolve(env.HDM_VPC.connect(BACKEND)).then(s => { if (expired) { void Promise.resolve(s.close()).catch(() => {}); throw new Error("expired"); } return s; });
      socket = await Promise.race([opening, new Promise((_, reject) => { timer = setTimeout(() => { expired = true; reject(new Error("timeout")); }, 5000); })]);
    } catch { return new Response("backend unavailable", { status: 502 }); }
    finally { clearTimeout(timer); }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    // 2026-03 起默认使用 Blob；在接收前固定为同步可检查的 ArrayBuffer。
    server.binaryType = "arraybuffer";
    server.accept();
    relay(server, socket);
    return new Response(null, { status: 101, webSocket: client });
  }
};
