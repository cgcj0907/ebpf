mod tracepoint;
use tracepoint::emit_http_status_udp;


use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, Interest};
use std::net::SocketAddr;
use std::sync::Mutex;
use tokio::signal;
use regex::Regex;
use lazy_static::lazy_static;
use deadpool::{managed::{Pool, Manager, Object, RecycleError, RecycleResult}};
use async_trait::async_trait;
use std::error::Error;
use deadpool::managed::PoolConfig;
use tokio::time::{timeout, Duration};
// --- 配置和全局状态 ---

#[derive(Debug, Clone)]
struct Config {
    proxy_addr: SocketAddr,
    backend_addr: SocketAddr,
}

#[derive(Debug, PartialEq, Eq)]
enum ConnectionState {
    NewConnection,
    ConnectingToBackend,
    WritingRequestHeader,
    ReadingResponseHeader,
    WritingResponseHeader,
    ForwardingResponse,
    Tunneling,
    Closed,
}

const BUFFER_SIZE: usize = 8192;
const CONFIG_FILE: &str = "config.conf";

// --- 连接池定义 ---

// TCP 连接管理器：实现 deadpool::Manager trait
struct TcpManager {
    addr: SocketAddr,
}

#[async_trait]
impl Manager for TcpManager {
    type Type = TcpStream;
    type Error = RecycleError<()>;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        TcpStream::connect(self.addr)   // 这里只用 .0
            .await
            .map_err(|e| RecycleError::Message(e.to_string()))
    }

    async fn recycle(&self, conn: &mut Self::Type, _: &deadpool::managed::Metrics) -> RecycleResult<Self::Error> {
        match timeout(Duration::from_millis(1), conn.ready(Interest::READABLE)).await {
            Ok(Ok(ready)) if ready.is_readable() => {
                let mut buf = [0u8; 1];
                match conn.try_read(&mut buf) {
                    Ok(0)  => Err(RecycleError::Message("EOF".into())),
                    Ok(_)  => Err(RecycleError::Message("unexpected data".into())),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
                    Err(e) => Err(RecycleError::Message(e.to_string())),
                }
            }
            _ => Err(RecycleError::Message("health check timeout".into())),
        }
    }
}

// 定义连接池类型别名
type TcpPool = Pool<TcpManager>;

// 静态全局变量，用于存储配置和连接池
lazy_static! {
    static ref CONNECTION_POOL: Mutex<Option<TcpPool>> = Mutex::new(None);
    static ref CONFIG: Mutex<Option<Config>> = Mutex::new(None);
}

// --- 辅助函数 ---

// 配置文件读取函数 (简化版，直接硬编码)
fn read_config() -> Result<Config, Box<dyn Error>> {
    println!("读取配置文件: {}", CONFIG_FILE);

    // 假设配置如下：
    let proxy_port = 8080;
    let backend_host = "127.0.0.1"; // 请替换为您的后端服务器地址
    let backend_port = 8000;

    let proxy_addr = format!("0.0.0.0:{}", proxy_port).parse()?;
    let backend_addr = format!("{}:{}", backend_host, backend_port).parse()?;

    println!("代理监听地址: {}", proxy_addr);
    println!("后端服务器: {}", backend_addr);

    Ok(Config { proxy_addr, backend_addr })
}

// 查找 HTTP 头部结束 (\r\n\r\n)
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    static HEADER_END: &[u8] = b"\r\n\r\n";
    buffer.windows(HEADER_END.len()).position(|window| window == HEADER_END)
}

// 修改请求头
fn modify_request_header(buffer: &[u8], backend_addr: SocketAddr) -> Option<(Vec<u8>, bool)> {
    let request_str = String::from_utf8_lossy(buffer);
    let mut lines = request_str.lines().peekable();
    if lines.peek().is_none() { return None; }

    let mut modified_request = String::new();
    let mut is_websocket = false;
    let backend_host_port = format!("{}", backend_addr);

    // 检查是否为 WebSocket
    if request_str.to_lowercase().contains("upgrade: websocket") && request_str.to_lowercase().contains("connection: upgrade") {
        is_websocket = true;
    }

    // 迭代并修改头部
    for line in lines {
        if line.is_empty() { continue; }

        let lower_line = line.to_lowercase();

        if lower_line.starts_with("host:") {
            // 重写 Host 头部
            modified_request.push_str(&format!("Host: {}\r\n", backend_host_port));
        } else if lower_line.starts_with("connection:") {
            // 重写 Connection 头部
            if !is_websocket {
                modified_request.push_str("Connection: close\r\n"); // HTTP/1.1 代理使用 close
            } else {
                modified_request.push_str(&format!("{}\r\n", line)); // WebSocket 保持
            }
        } else {
            // 复制其他头部 (包括请求行)
            modified_request.push_str(&format!("{}\r\n", line));
        }
    }

    // 附加空行以结束头部
    modified_request.push_str("\r\n");

    // 复制请求体 (如果有)
    if let Some(header_end_pos) = find_header_end(buffer) {
        let body_start = header_end_pos + 4;
        let body = &buffer[body_start..];

        let mut result_vec = modified_request.into_bytes();
        result_vec.extend_from_slice(body);
        return Some((result_vec, is_websocket));
    }

    // 如果没有 body，只返回头部
    Some((modified_request.into_bytes(), is_websocket))
}


// --- 核心代理逻辑 ---

async fn proxy_stream(mut client_stream: TcpStream, pool: TcpPool) {
    let client_addr = match client_stream.peer_addr() {
        Ok(addr) => format!("{}", addr),
        Err(_) => "unknown".to_string(),
    };

    let (mut client_reader, mut client_writer) = client_stream.split();

    let mut state = ConnectionState::NewConnection;
    let mut is_websocket = false;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut bytes_read = 0;

    // 查找配置中的后端地址，用于修改 Host 头
    let backend_addr = match CONFIG.lock().unwrap().as_ref() {
        Some(cfg) => cfg.backend_addr,
        None => {
            eprintln!("[{}] Configuration missing!", client_addr);
            return;
        }
    };

    // --- 1. 读取客户端请求头 ---
    loop {
        match client_reader.read(&mut buffer[bytes_read..]).await {
            Ok(0) => {
                println!("[{}] Client closed connection during header read.", client_addr);
                return;
            }
            Ok(n) => {
                bytes_read += n;
                if let Some(header_end_pos) = find_header_end(&buffer[..bytes_read]) {

                    let header_len = header_end_pos + 4;
                    buffer.truncate(bytes_read); // 截断到实际读取的字节数

                    // --- 2. 处理和修改请求头 ---
                    let (modified_request, is_ws) = match modify_request_header(&buffer[..bytes_read], backend_addr) {
                        Some(result) => result,
                        None => {
                            eprintln!("[{}] Failed to process request header.", client_addr);
                            return;
                        }
                    };

                    is_websocket = is_ws;
                    state = ConnectionState::ConnectingToBackend;

                    // --- 3. 从连接池获取连接并发送请求 ---
                    // **【修正：增加 5 秒获取连接超时】**
                    let timeout_duration = Duration::from_secs(5);
                    let mut backend_connection = match timeout(timeout_duration, pool.get()).await {
                        Ok(Ok(conn_obj)) => conn_obj,
                        Ok(Err(e)) => {
                            eprintln!("[{}] Failed to get backend connection from pool (deadpool error): {:?}", client_addr, e);
                            // 尝试返回 503 给客户端
                            let _ = client_writer.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n").await;
                            return;
                        }
                        Err(_) => { // Timeout 发生
                            eprintln!("[{}] Failed to get backend connection from pool (timeout).", client_addr);
                            // 尝试返回 503 给客户端
                            let _ = client_writer.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n").await;
                            return;
                        }
                    };

                    // 获取连接的读写部分
                    let (mut backend_reader, mut backend_writer) = backend_connection.split();

                    state = ConnectionState::WritingRequestHeader;

                    // 写入修改后的请求头和剩余的 body
                    if let Err(e) = backend_writer.write_all(&modified_request).await {
                        eprintln!("[{}] Failed to write request to backend: {}", client_addr, e);
                        return;
                    }
                    state = ConnectionState::ReadingResponseHeader;

                    // --- 4. 转发逻辑 (HTTP 或 WebSocket) ---
                    if is_websocket {
                        println!("[{}] WebSocket initiated. Switching to tunnel mode.", client_addr);
                        state = ConnectionState::Tunneling;

                        // 双向转发 (非零拷贝)
                        let client_to_backend = tokio::io::copy(&mut client_reader, &mut backend_writer);
                        let backend_to_client = tokio::io::copy(&mut backend_reader, &mut client_writer);

                        // 并发等待任一方向关闭
                        tokio::select! {
                            _ = client_to_backend => {},
                            _ = backend_to_client => {},
                        }

                    } else {
                        // HTTP 代理模式：读取响应头并转发
                        let mut response_buffer = vec![0u8; BUFFER_SIZE];
                        let mut response_bytes_read = 0;

                        // 循环读取响应头
                        loop {
                            match backend_reader.read(&mut response_buffer[response_bytes_read..]).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    response_bytes_read += n;
                                    if let Some(_) = find_header_end(&response_buffer[..response_bytes_read]) {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[{}] Error reading response header from backend: {}", client_addr, e);
                                    return;
                                }
                            }
                            if response_bytes_read >= BUFFER_SIZE { break; }
                        }

                        if response_bytes_read > 0 {
                            // 发送响应头给客户端
                            if let Err(e) = client_writer.write_all(&response_buffer[..response_bytes_read]).await {
                                eprintln!("[{}] Failed to write response header to client: {}", client_addr, e);
                                return;
                            } else {

                             if let Ok(header_str) = String::from_utf8(response_buffer[..response_bytes_read].to_vec()) {
                                    if let Some(code_str) = header_str.split_whitespace().nth(1) {
                                        if let Ok(code) = code_str.parse::<u16>() {
                                            emit_http_status_udp(code);
                                        }
                                    }
                                }
                            }

                            state = ConnectionState::ForwardingResponse;

                            // 转发剩余的响应体 (非零拷贝)
                            if let Err(e) = tokio::io::copy(&mut backend_reader, &mut client_writer).await {
                                eprintln!("[{}] Error during response body forwarding: {}", client_addr, e);
                            }
                            // 【关键修正：显式关闭客户端写入端】
                            if let Err(e) = client_writer.shutdown().await { // <--- 这里是问题所在
                                eprintln!("[{}] Error shutting down client writer: {}", client_addr, e);
                            }
                            break;
                        }
                    }

                    // 后端连接 (backend_connection) 在这里离开作用域，自动归还给连接池
                    break;
                }
            }
            Err(e) => {
                eprintln!("[{}] Error reading from client: {}", client_addr, e);
                return;
            }
        }
    }

    state = ConnectionState::Closed;
    println!("[{}] Connection finished. Final State: {:?}", client_addr, state);
}


// --- 主函数 ---

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // --- 1. 读取配置 ---
    let config = read_config()?;
    *CONFIG.lock().unwrap() = Some(config.clone());

    // --- 2. 初始化连接池 ---
    let manager = TcpManager { addr: config.backend_addr };
    // 配置连接池：最大连接数 10
    let pool_config = deadpool::managed::PoolConfig {
        max_size: 100,
        ..Default::default()
    };

    // 2. 将配置传递给 PoolBuilder
    let pool = Pool::builder(manager)
        .config(pool_config) // ✅ 使用 config() 方法传递配置
        .build()?;

    *CONNECTION_POOL.lock().unwrap() = Some(pool.clone());
    println!("Backend TCP Pool initialized (Max: 10, Min idle: 2).");

    // --- 3. 启动监听器 ---
    let listener = TcpListener::bind(config.proxy_addr).await?;
    println!("Proxy listening on {}", config.proxy_addr);

    // --- 4. 信号处理 (优雅关停) ---
    let mut sigint = signal::ctrl_c();

    // --- 5. 主事件循环 ---
    loop {
        let sigint = signal::ctrl_c();
        tokio::select! {
            // 优雅关停
            _ = sigint => {
            println!("\n[Signal] Shutting down gracefully...");
            break;
        },

            // 接受新连接
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let proxy_pool = pool.clone();
                        // 为每个新连接创建一个异步任务 (Future)
                        tokio::spawn(async move {
                            proxy_stream(stream, proxy_pool).await;
                        });
                    }
                    Err(e) => {
                        eprintln!("Error accepting connection: {}", e);
                    }
                }
            }
        }
    }

    println!("Proxy shut down completely.");
    Ok(())
}
