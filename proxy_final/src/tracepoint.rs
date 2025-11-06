// src/tracepoint.rs
use std::net::UdpSocket;

/// emit_http_status_udp(code): 通过本地 UDP 把 HTTP 状态码上报到 127.0.0.1:42424
/// 非阻塞、尽量不panic：尽量不影响主逻辑
pub fn emit_http_status_udp(code: u16) {
    // format like "200\n"
    let msg = format!("{}\n", code);
    // we create socket and send; overhead is minimal for occasional responses
    if let Ok(socket) = UdpSocket::bind("127.0.0.1:0") {
        let _ = socket.set_nonblocking(true);
        let _ = socket.send_to(msg.as_bytes(), "127.0.0.1:42424");
        // ignore errors
    }
}

