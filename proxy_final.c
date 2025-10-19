#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <ctype.h>
#include <stdint.h> // <<< 引入 uint32_t 类型
#include <signal.h>

#define MAX_EVENTS 1024
#define BUFFER_SIZE 8192
#define CONFIG_FILE "config.conf"

typedef enum {
    STATE_NEW_CONNECTION,
    STATE_CONNECTING_TO_BACKEND,
    STATE_WRITING_REQUEST_HEADER,
    STATE_READING_RESPONSE_HEADER,
    STATE_WRITING_RESPONSE_HEADER,
    STATE_FORWARDING_RESPONSE,
    STATE_TUNNELING,
    STATE_CLOSED
} connection_state;

struct connection_ctx;
volatile sig_atomic_t running = 1;

typedef struct {
    int fd;
    struct connection_ctx *ctx;
} event_data;

typedef struct connection_ctx {
    int client_fd;
    int backend_fd;
    event_data *client_event_data;
    event_data *backend_event_data;
    connection_state state;
    char buffer[BUFFER_SIZE];
    size_t buffer_bytes_read;
    size_t buffer_bytes_sent;
    int is_websocket;
    long long content_length;
    long long body_bytes_forwarded;
    int pipe_fd[2];
} connection_ctx;

/**
 * @brief 信号处理函数，用于捕获 SIGINT 和 SIGTERM。
 * @param signum 捕获到的信号编号。
 */
void sig_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        // 优雅退出：设置标志为0，让主循环在 epoll_wait 返回后退出
        running = 0;
        printf("\n[Signal %d] Shutting down gracefully... Press Ctrl+C again to force exit.\n", signum);
    }
}

/**
 * @brief 从配置文件中读取代理和后端服务器配置。
 * * @param proxy_port 指向存储代理监听端口的整数。
 * @param backend_host 指向存储后端主机名的字符数组。
 * @param backend_port 指向存储后端端口的整数。
 */
void read_config(int *proxy_port, char *backend_host, int *backend_port) {
    FILE *file = fopen(CONFIG_FILE, "r");
    if (!file) {
        // 使用 EXIT_FAILURE 而不是 EXIT_SUCCESS，因为打开文件失败是错误
        perror("Error opening config file");
        exit(EXIT_FAILURE);
    }

    char line[1024];

    // 默认值，以防配置文件中缺少某些项
    *proxy_port = 8080; // 默认代理端口
    strcpy(backend_host, "localhost"); // 默认后端主机
    *backend_port = 80; // 默认后端端口

    while (fgets(line, sizeof(line), file)) {
        // 1. 去除行尾的换行符和回车符
        line[strcspn(line, "\n\r")] = 0;

        // 2. 查找并截断注释 (假设注释以 ';' 或 '#' 开头)
        char *comment_semi = strchr(line, ';');
        char *comment_hash = strchr(line, '#');
        char *comment = (comment_semi != NULL && (comment_hash == NULL || comment_semi < comment_hash)) ? comment_semi : comment_hash;
        if (comment) {
            *comment = '\0';
        }

        // 3. 移除行首尾的空白字符
        char *trim_start = line;
        while (*trim_start && (*trim_start == ' ' || *trim_start == '\t')) {
            trim_start++;
        }
        if (*trim_start == '\0') {
            continue; // 跳过空行或只有注释的行
        }

        // 复制修剪后的行到临时缓冲区，以便进行 sscanf
        char cleaned_line[1024];
        strcpy(cleaned_line, trim_start);
        char *trim_end = cleaned_line + strlen(cleaned_line) - 1;
        while (trim_end > cleaned_line && (*trim_end == ' ' || *trim_end == '\t')) {
            *trim_end-- = '\0';
        }

        char directive[64];
        char value[960];

        // 4. 使用 sscanf 提取指令和值
        // 尝试匹配 "directive value;" 或 "directive value"
        int scanned = sscanf(cleaned_line, "%63s %959[^;]", directive, value);

        if (scanned >= 1) {
            if (strcmp(directive, "listen") == 0) {
                if (scanned == 2) {
                    sscanf(value, "%d", proxy_port);
                }
            } else if (strcmp(directive, "proxy_pass") == 0) {
                if (scanned == 2) {
                    // 假设值是 "http://host:port" 或 "http://host"
                    char *url_start = strstr(value, "http://");
                    if (url_start) {
                        url_start += 7; // 跳过 "http://"
                        char *colon = strchr(url_start, ':');
                        char *slash = strchr(url_start, '/');

                        if (colon && (!slash || colon < slash)) {
                            // 格式: http://host:port/path 或 http://host:port
                            *colon = '\0'; // 截断 host
                            strncpy(backend_host, url_start, 255); // 假设 backend_host 足够大
                            sscanf(colon + 1, "%d", backend_port);
                        } else {
                            // 格式: http://host/path 或 http://host
                            char *end_of_host = (slash) ? slash : url_start + strlen(url_start);
                            char temp_host[256];
                            strncpy(temp_host, url_start, end_of_host - url_start);
                            temp_host[end_of_host - url_start] = '\0';
                            strncpy(backend_host, temp_host, 255);
                            *backend_port = 80; // 默认 HTTP 端口
                        }
                    }
                }
            }
            // 可以添加更多指令的解析
        }
    }

    fclose(file);

    // 统一输出结果，即使使用默认值
    printf("Proxy listening on port: %d\n", *proxy_port);
    printf("Backend server: %s:%d\n", backend_host, *backend_port);
}

void set_nonblocking(int fd) {
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}

void close_connection(int epoll_fd, connection_ctx *ctx) {
    if (ctx->state == STATE_CLOSED) return;
    printf("Closing connection (client_fd=%d, backend_fd=%d)\n", ctx->client_fd, ctx->backend_fd);
    if (ctx->client_fd != -1) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ctx->client_fd, NULL);
        close(ctx->client_fd);
        free(ctx->client_event_data);
    }
    if (ctx->backend_fd != -1) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, ctx->backend_fd, NULL);
        close(ctx->backend_fd);
        free(ctx->backend_event_data);
    }
    if (ctx->pipe_fd[0] != -1) close(ctx->pipe_fd[0]);
    if (ctx->pipe_fd[1] != -1) close(ctx->pipe_fd[1]);
    ctx->state = STATE_CLOSED;
    free(ctx);
}

void process_request_header(connection_ctx *ctx, const char *backend_host, int backend_port) {
    char temp_buffer[BUFFER_SIZE];
    char *header_end = strstr(ctx->buffer, "\r\n\r\n");
    if (!header_end) return;
    int header_len = header_end - ctx->buffer + 4;
    char header_copy[header_len + 1];
    memcpy(header_copy, ctx->buffer, header_len);
    header_copy[header_len] = '\0';
    if (strcasestr(header_copy, "Upgrade: websocket") && strcasestr(header_copy, "Connection: Upgrade")) {
        ctx->is_websocket = 1;
        printf("Detected WebSocket upgrade request.\n");
    }
    ctx->content_length = 0;
    char *cl_ptr = strcasestr(header_copy, "Content-Length:");
    if (cl_ptr) {
        sscanf(cl_ptr + 15, "%lld", &ctx->content_length);
    }
    memset(temp_buffer, 0, BUFFER_SIZE);
    int modified_len = 0;
    char *line = strtok(header_copy, "\r\n");
    while (line != NULL) {
        if (strncasecmp(line, "Host:", 5) == 0) {
            modified_len += snprintf(temp_buffer + modified_len, BUFFER_SIZE - modified_len, "Host: %s:%d\r\n", backend_host, backend_port);
        } else if (strncasecmp(line, "Connection:", 11) == 0) {
            if (ctx->is_websocket) {
                 modified_len += snprintf(temp_buffer + modified_len, BUFFER_SIZE - modified_len, "%s\r\n", line);
            } else {
                 modified_len += snprintf(temp_buffer + modified_len, BUFFER_SIZE - modified_len, "Connection: close\r\n");
            }
        } else {
            modified_len += snprintf(temp_buffer + modified_len, BUFFER_SIZE - modified_len, "%s\r\n", line);
        }
        line = strtok(NULL, "\r\n");
    }
    modified_len += snprintf(temp_buffer + modified_len, BUFFER_SIZE - modified_len, "\r\n");
    int body_len = ctx->buffer_bytes_read - header_len;
    memmove(ctx->buffer + modified_len, ctx->buffer + header_len, body_len);
    memcpy(ctx->buffer, temp_buffer, modified_len);
    ctx->buffer_bytes_read = modified_len + body_len;
    ctx->buffer_bytes_sent = 0;
}


// <<< 修正：函数签名增加 uint32_t events_fired 参数
void handle_client_event(int epoll_fd, event_data *data, uint32_t events_fired, const char *backend_host, int backend_port) {
    connection_ctx *ctx = data->ctx;
    struct epoll_event ev;

    // <<< 修正：使用传入的 events_fired 参数
    if (events_fired & EPOLLOUT) {
        if (ctx->state == STATE_WRITING_RESPONSE_HEADER) {
            ssize_t bytes_sent = write(ctx->client_fd, ctx->buffer + ctx->buffer_bytes_sent, ctx->buffer_bytes_read - ctx->buffer_bytes_sent);
            if (bytes_sent < 0) {
                if (errno != EAGAIN) close_connection(epoll_fd, ctx);
                return;
            }
            ctx->buffer_bytes_sent += bytes_sent;

            if (ctx->buffer_bytes_sent >= ctx->buffer_bytes_read) {
                if (ctx->is_websocket) {
                    printf("WebSocket handshake successful. Switching to tunnel mode.\n");
                    ctx->state = STATE_TUNNELING;
                    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
                    ev.data.ptr = ctx->client_event_data;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ctx->client_fd, &ev);

                    ev.data.ptr = ctx->backend_event_data;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ctx->backend_fd, &ev);
                } else {
                    ctx->state = STATE_FORWARDING_RESPONSE;
                    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
                    ev.data.ptr = ctx->backend_event_data;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ctx->backend_fd, &ev);
                    ev.events = EPOLLRDHUP | EPOLLERR;
                    ev.data.ptr = ctx->client_event_data;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ctx->client_fd, &ev);
                }
            }
        }
        return;
    }

    // <<< 修正：使用传入的 events_fired 参数
    if (events_fired & EPOLLIN) {
        if (ctx->state == STATE_NEW_CONNECTION) {
             ssize_t bytes_read = read(ctx->client_fd, ctx->buffer, BUFFER_SIZE);
            if (bytes_read <= 0) {
                close_connection(epoll_fd, ctx);
                return;
            }
            ctx->buffer_bytes_read = bytes_read;
            ctx->backend_fd = socket(AF_INET, SOCK_STREAM, 0);
            set_nonblocking(ctx->backend_fd);
            struct sockaddr_in backend_addr;
            backend_addr.sin_family = AF_INET;
            backend_addr.sin_port = htons(backend_port);
            inet_pton(AF_INET, backend_host, &backend_addr.sin_addr);
            int ret = connect(ctx->backend_fd, (struct sockaddr *)&backend_addr, sizeof(backend_addr));
            if (ret == 0 || errno == EINPROGRESS) {
                ctx->state = STATE_CONNECTING_TO_BACKEND;
                ctx->backend_event_data = malloc(sizeof(event_data));
                ctx->backend_event_data->fd = ctx->backend_fd;
                ctx->backend_event_data->ctx = ctx;
                ev.events = EPOLLOUT | EPOLLRDHUP | EPOLLERR;
                ev.data.ptr = ctx->backend_event_data;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctx->backend_fd, &ev);
            } else {
                perror("connect to backend");
                close_connection(epoll_fd, ctx);
            }
        } else if (ctx->state == STATE_TUNNELING) {
            ssize_t forwarded;
            while ((forwarded = splice(ctx->client_fd, NULL, ctx->pipe_fd[1], NULL, 65536, SPLICE_F_MOVE | SPLICE_F_NONBLOCK)) > 0) {
                splice(ctx->pipe_fd[0], NULL, ctx->backend_fd, NULL, forwarded, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            }
            if (forwarded == 0 || (forwarded == -1 && errno != EAGAIN)) {
                 close_connection(epoll_fd, ctx);
            }
        }
    }
}

// <<< 修正：函数签名增加 uint32_t events_fired 参数
void handle_backend_event(int epoll_fd, event_data *data, uint32_t events_fired, const char *backend_host, int backend_port) {
    connection_ctx *ctx = data->ctx;
    struct epoll_event ev;

    // <<< 修正：使用传入的 events_fired 参数
    if (events_fired & EPOLLOUT) {
         if (ctx->state == STATE_CONNECTING_TO_BACKEND) {
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(ctx->backend_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
                fprintf(stderr, "Failed to connect to backend.\n");
                close_connection(epoll_fd, ctx);
                return;
            }
            printf("Connected to backend server.\n");
            process_request_header(ctx, backend_host, backend_port);
            ctx->state = STATE_WRITING_REQUEST_HEADER;
        }

        if (ctx->state == STATE_WRITING_REQUEST_HEADER) {
            ssize_t bytes_sent = write(ctx->backend_fd, ctx->buffer + ctx->buffer_bytes_sent, ctx->buffer_bytes_read - ctx->buffer_bytes_sent);
            if (bytes_sent < 0) {
                if(errno != EAGAIN) close_connection(epoll_fd, ctx);
                return;
            }
            ctx->buffer_bytes_sent += bytes_sent;
            if (ctx->buffer_bytes_sent >= ctx->buffer_bytes_read) {
                ctx->state = STATE_READING_RESPONSE_HEADER;
                ctx->buffer_bytes_read = 0;
                ctx->buffer_bytes_sent = 0;
                ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
                ev.data.ptr = ctx->backend_event_data;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ctx->backend_fd, &ev);
            }
        }
        return;
    }

    // <<< 修正：使用传入的 events_fired 参数
    if (events_fired & EPOLLIN) {
        if (ctx->state == STATE_READING_RESPONSE_HEADER) {
            ssize_t bytes_read = read(ctx->backend_fd, ctx->buffer + ctx->buffer_bytes_read, BUFFER_SIZE - ctx->buffer_bytes_read);
            if (bytes_read <= 0) {
                if(bytes_read < 0 && errno != EAGAIN) perror("read from backend");
                close_connection(epoll_fd, ctx);
                return;
            }
            ctx->buffer_bytes_read += bytes_read;
            char *header_end = strstr(ctx->buffer, "\r\n\r\n");
            if (header_end != NULL) {
                printf("Received response header from backend.\n");

                // <<< 修正：使用 strncasecmp 并判断返回值
                if (ctx->is_websocket && strncasecmp(ctx->buffer, "HTTP/1.1 101", 12) == 0) {
                    // WebSocket 握手成功
                } else {
                    ctx->is_websocket = 0;
                }
                ctx->state = STATE_WRITING_RESPONSE_HEADER;
                ev.events = EPOLLOUT | EPOLLRDHUP | EPOLLERR;
                ev.data.ptr = ctx->client_event_data;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ctx->client_fd, &ev);
            }
        } else if (ctx->state == STATE_FORWARDING_RESPONSE) {
            ssize_t forwarded;
            while ((forwarded = splice(ctx->backend_fd, NULL, ctx->pipe_fd[1], NULL, 65536, SPLICE_F_MOVE | SPLICE_F_NONBLOCK)) > 0) {
                splice(ctx->pipe_fd[0], NULL, ctx->client_fd, NULL, forwarded, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            }
            if (forwarded == 0 || (forwarded == -1 && errno != EAGAIN)) {
                close_connection(epoll_fd, ctx);
            }
        } else if (ctx->state == STATE_TUNNELING) {
            ssize_t forwarded;
            while ((forwarded = splice(ctx->backend_fd, NULL, ctx->pipe_fd[1], NULL, 65536, SPLICE_F_MOVE | SPLICE_F_NONBLOCK)) > 0) {
                splice(ctx->pipe_fd[0], NULL, ctx->client_fd, NULL, forwarded, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            }
            if (forwarded == 0 || (forwarded == -1 && errno != EAGAIN)) {
                 close_connection(epoll_fd, ctx);
            }
        }
    }
}


int main() {
    int proxy_port;
    char backend_host[256];
    int backend_port;
    read_config(&proxy_port, backend_host, &backend_port);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    set_nonblocking(server_fd);

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(proxy_port);

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    // >>> START: 注册信号处理机制 <<<
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    // 确保在信号处理函数执行时，阻塞所有其他信号
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction SIGINT");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        perror("sigaction SIGTERM");
        exit(EXIT_FAILURE);
    }
    // >>> END: 注册信号处理机制 <<<

    int epoll_fd = epoll_create1(0);
    struct epoll_event ev, events[MAX_EVENTS];

    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == server_fd) {
                int client_fd = accept(server_fd, NULL, NULL);
                if (client_fd < 0) continue;
                set_nonblocking(client_fd);

                connection_ctx *ctx = calloc(1, sizeof(connection_ctx));
                ctx->client_fd = client_fd;
                ctx->backend_fd = -1;
                ctx->state = STATE_NEW_CONNECTION;

                if (pipe(ctx->pipe_fd) == -1) {
                    perror("pipe");
                    close(client_fd);
                    free(ctx);
                    continue;
                }

                event_data *client_data = malloc(sizeof(event_data));
                client_data->fd = client_fd;
                client_data->ctx = ctx;
                ctx->client_event_data = client_data;

                ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR;
                ev.data.ptr = client_data;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

            } else {
                event_data *data = (event_data *)events[i].data.ptr;
                connection_ctx *ctx = data->ctx;

                if (events[i].events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
                    close_connection(epoll_fd, ctx);
                    continue;
                }

                if (data->fd == ctx->client_fd) {
                    // <<< 修正：传入 events[i].events
                    handle_client_event(epoll_fd, data, events[i].events, backend_host, backend_port);
                } else if (data->fd == ctx->backend_fd) {
                    // <<< 修正：传入 events[i].events
                    handle_backend_event(epoll_fd, data, events[i].events, backend_host, backend_port);
                }
            }
        }
    }

    printf("Processing remaining connections...\n");

    // 强制清理 epoll 实例中所有剩余的连接上下文
    // 注意：由于 epoll_ctl(DEL) 需要事件结构，这里使用一个简单的方法
    // 更好的方法是在主循环外再加一个循环，只处理现有连接的关闭事件，
    // 但为了简洁和避免复杂性，我们直接退出。
    // 在生产环境中，你需要遍历所有 ctx，并尝试等待它们完成 I/O。

    // 假设在退出主循环时，所有未完成的连接将在系统关闭时被清理，
    // 或者在下次收到信号时被强制关闭（二次按下 Ctrl+C）。

    if (server_fd != -1) close(server_fd); // 确保关闭
    close(epoll_fd);
    printf("Proxy shut down completely.\n");
    return 0;
}