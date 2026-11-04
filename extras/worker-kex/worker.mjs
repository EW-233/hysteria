import { connect } from 'cloudflare:sockets';
import { createWorker } from './relay.mjs';

// 每个 POST 独立连接固定 TLS 上游，不保留连接池或自动重试。
export default createWorker(connect);
