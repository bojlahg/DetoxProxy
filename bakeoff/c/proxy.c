#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#define MAX_UPSTREAMS 16
#define MAX_EVENTS 1024

/* ------------------------------------------------------------------ buffers */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
    size_t off;
} Buf;

static void buf_ensure(Buf *b, size_t extra) {
    if (b->len + extra <= b->cap) return;
    size_t ncap = b->cap ? b->cap : 256;
    while (ncap < b->len + extra) ncap *= 2;
    b->data = realloc(b->data, ncap);
    b->cap = ncap;
}

static void buf_append(Buf *b, const void *data, size_t n) {
    if (n == 0) return;
    buf_ensure(b, n);
    memcpy(b->data + b->len, data, n);
    b->len += n;
}

static void buf_reset(Buf *b) {
    b->len = 0;
    b->off = 0;
}

static void buf_free(Buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = b->off = 0;
}

static char *find_sub(const char *hay, size_t hlen, const char *needle, size_t nlen) {
    if (nlen == 0) return (char *)hay;
    if (hlen < nlen) return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return (char *)(hay + i);
    }
    return NULL;
}

/* ------------------------------------------------------------------ conn */

typedef struct Conn Conn;

enum {
    ST_READ_REQUEST = 0,
    ST_CONNECT,
    ST_SEND_REQUEST,
    ST_WAIT_HEADERS,
    ST_WAIT_FIRST_BODY,
    ST_STREAM,
    ST_DONE,
    ST_ERROR
};

struct Conn {
    int fd;
    int state;
    int closed;

    Buf req;
    int req_headers_done;
    int req_complete;
    size_t req_header_len;
    char method[16];
    char path[512];
    int req_has_cl;
    size_t req_content_length;
    int req_chunked;
    int is_stream;

    Buf out;
    int first_byte_sent;
    int close_after_flush;

    int up_fd;
    int up_connected;
    int up_headers_parsed;
    size_t up_header_len;
    int up_status;
    int up_chunked;
    int up_has_cl;
    size_t up_content_length;
    size_t up_body_received;
    int up_index;
    int up_ttft_active;
    uint64_t up_ttft_deadline;
    Buf up_in;
    Buf up_out;
};

/* ------------------------------------------------------------------ globals */

static int g_epfd = -1;
static int g_listen_fd = -1;
static int g_ttft_ms = 5000;
static char *g_upstreams[MAX_UPSTREAMS];
static int g_n_upstreams = 0;
static uint64_t g_requests_total = 0;

static Conn **g_conns = NULL;
static size_t g_conns_cap = 0;

static void conn_set(int fd, Conn *c) {
    if (fd < 0) return;
    if ((size_t)fd >= g_conns_cap) {
        size_t ncap = g_conns_cap ? g_conns_cap : 64;
        while (ncap <= (size_t)fd) ncap *= 2;
        g_conns = realloc(g_conns, ncap * sizeof(Conn *));
        for (size_t i = g_conns_cap; i < ncap; i++) g_conns[i] = NULL;
        g_conns_cap = ncap;
    }
    g_conns[fd] = c;
}

static Conn *conn_get(int fd) {
    if (fd < 0 || (size_t)fd >= g_conns_cap) return NULL;
    return g_conns[fd];
}

static void free_conn(Conn *c) {
    if (!c) return;
    buf_free(&c->req);
    buf_free(&c->out);
    buf_free(&c->up_in);
    buf_free(&c->up_out);
    free(c);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static const char *status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 404: return "Not Found";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default: return "Unknown";
    }
}

/* ------------------------------------------------------------------ helpers */

static void update_events(Conn *c);
static void close_conn(Conn *c);
static void failover(Conn *c);
static void start_connect(Conn *c);
static void flush_upstream(Conn *c);
static void process_upstream(Conn *c);
static void check_completion(Conn *c);
static void finish_response(Conn *c);
static void finish_client(Conn *c);
static void handle_request(Conn *c);

static void close_upstream(Conn *c) {
    if (c->up_fd >= 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, c->up_fd, NULL);
        conn_set(c->up_fd, NULL);
        close(c->up_fd);
        c->up_fd = -1;
    }
    c->up_ttft_active = 0;
}

static void close_conn(Conn *c) {
    if (c->closed) return;
    c->closed = 1;
    int cfd = c->fd;
    int ufd = c->up_fd;
    if (cfd >= 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, cfd, NULL);
        close(cfd);
        c->fd = -1;
    }
    if (ufd >= 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, ufd, NULL);
        close(ufd);
        c->up_fd = -1;
    }
    c->up_ttft_active = 0;
    conn_set(cfd, NULL);
    conn_set(ufd, NULL);
}

static void update_events(Conn *c) {
    if (c->fd >= 0) {
        uint32_t ev = EPOLLIN;
        if (c->out.off < c->out.len) ev |= EPOLLOUT;
        struct epoll_event e;
        e.events = ev;
        e.data.fd = c->fd;
        epoll_ctl(g_epfd, EPOLL_CTL_MOD, c->fd, &e);
    }
    if (c->up_fd >= 0) {
        uint32_t ev = 0;
        if (c->state == ST_CONNECT || c->up_out.off < c->up_out.len) ev |= EPOLLOUT;
        if (c->state == ST_WAIT_HEADERS || c->state == ST_WAIT_FIRST_BODY || c->state == ST_STREAM)
            ev |= EPOLLIN;
        struct epoll_event e;
        e.events = ev;
        e.data.fd = c->up_fd;
        epoll_ctl(g_epfd, EPOLL_CTL_MOD, c->up_fd, &e);
    }
}

static void forward_to_client(Conn *c, const char *data, size_t len) {
    if (len == 0) return;
    if (c->out.len == 0) c->first_byte_sent = 1;
    buf_append(&c->out, data, len);
    update_events(c);
}

static void send_simple(Conn *c, int status, const char *ct, const char *body) {
    char head[256];
    int hn = snprintf(head, sizeof(head),
        "HTTP/1.1 %d %s\r\ncontent-type: %s\r\ncontent-length: %zu\r\nconnection: close\r\n\r\n",
        status, status_text(status), ct, strlen(body));
    buf_append(&c->out, head, hn);
    buf_append(&c->out, body, strlen(body));
    c->state = ST_DONE;
    c->close_after_flush = 1;
    update_events(c);
    if (c->out.off >= c->out.len) close_conn(c);
}

static void send_error(Conn *c, int status, const char *msg) {
    char body[512];
    int bn = snprintf(body, sizeof(body),
        "{\"error\": {\"message\": \"%s\", \"type\": \"upstream_error\"}}", msg);
    char head[256];
    int hn = snprintf(head, sizeof(head),
        "HTTP/1.1 %d %s\r\ncontent-type: application/json\r\ncontent-length: %d\r\nconnection: close\r\n\r\n",
        status, status_text(status), bn);
    buf_append(&c->out, head, hn);
    buf_append(&c->out, body, bn);
    c->state = ST_ERROR;
    c->close_after_flush = 1;
    update_events(c);
    if (c->out.off >= c->out.len) close_conn(c);
}

/* ------------------------------------------------------------------ parsing */

static void parse_request_headers(Conn *c, const char *data, size_t len) {
    const char *sp1 = memchr(data, ' ', len);
    if (!sp1) return;
    size_t mlen = sp1 - data;
    if (mlen < sizeof(c->method)) {
        memcpy(c->method, data, mlen);
        c->method[mlen] = 0;
    }
    const char *sp2 = memchr(sp1 + 1, ' ', len - (size_t)(sp1 + 1 - data));
    if (!sp2) return;
    size_t plen = sp2 - (sp1 + 1);
    if (plen < sizeof(c->path)) {
        memcpy(c->path, sp1 + 1, plen);
        c->path[plen] = 0;
    }
    const char *h = sp2;
    const char *end = data + len;
    while (h < end) {
        const char *nl = memchr(h, '\n', end - h);
        if (!nl) break;
        size_t llen = nl - h;
        if (llen >= 2 && h[llen - 1] == '\r') llen--;
        const char *colon = memchr(h, ':', llen);
        if (colon) {
            size_t klen = colon - h;
            const char *v = colon + 1;
            while (v < h + llen && (*v == ' ' || *v == '\t')) v++;
            if (klen == 14 && strncasecmp(h, "content-length", 14) == 0) {
                c->req_has_cl = 1;
                c->req_content_length = strtoull(v, NULL, 10);
            } else if (klen == 17 && strncasecmp(h, "transfer-encoding", 17) == 0) {
                if (strncasecmp(v, "chunked", 7) == 0) c->req_chunked = 1;
            }
        }
        h = nl + 1;
    }
}

static void parse_upstream_headers(Conn *c, const char *data, size_t len) {
    const char *p = data;
    const char *end = data + len;
    while (p < end && *p != ' ') p++;
    p++;
    int status = 0;
    while (p < end && *p != ' ') {
        if (*p >= '0' && *p <= '9') status = status * 10 + (*p - '0');
        p++;
    }
    c->up_status = status;
    const char *h = data;
    while (h < end) {
        const char *nl = memchr(h, '\n', end - h);
        if (!nl) break;
        size_t llen = nl - h;
        if (llen >= 2 && h[llen - 1] == '\r') llen--;
        const char *colon = memchr(h, ':', llen);
        if (colon) {
            size_t klen = colon - h;
            const char *v = colon + 1;
            while (v < h + llen && (*v == ' ' || *v == '\t')) v++;
            if (klen == 14 && strncasecmp(h, "content-length", 14) == 0) {
                c->up_has_cl = 1;
                c->up_content_length = strtoull(v, NULL, 10);
            } else if (klen == 17 && strncasecmp(h, "transfer-encoding", 17) == 0) {
                if (strncasecmp(v, "chunked", 7) == 0) c->up_chunked = 1;
            }
        }
        h = nl + 1;
    }
}

static int body_is_stream(const char *body, size_t len) {
    const char *p = body;
    const char *end = body + len;
    while (p < end) {
        const char *q = find_sub(p, end - p, "\"stream\"", 8);
        if (!q) break;
        const char *c = q + 8;
        while (c < end && (*c == ' ' || *c == '\t' || *c == ':')) c++;
        while (c < end && (*c == ' ' || *c == '\t')) c++;
        if (c < end && strncmp(c, "true", 4) == 0) return 1;
        p = q + 8;
    }
    return 0;
}

/* ------------------------------------------------------------------ request handling */

static void try_complete_request(Conn *c) {
    if (c->req_complete) return;
    if (!c->req_headers_done) {
        char *hdr_end = find_sub(c->req.data, c->req.len, "\r\n\r\n", 4);
        if (hdr_end) {
            c->req_headers_done = 1;
            c->req_header_len = (size_t)(hdr_end + 4 - c->req.data);
            parse_request_headers(c, c->req.data, c->req_header_len);
        } else {
            return;
        }
    }
    if (c->req_has_cl) {
        if (c->req.len >= c->req_header_len + c->req_content_length) c->req_complete = 1;
    } else if (c->req_chunked) {
        if (find_sub(c->req.data, c->req.len, "\r\n0\r\n\r\n", 8)) c->req_complete = 1;
    } else {
        c->req_complete = 1;
    }
    if (c->req_complete) handle_request(c);
}

static void handle_request(Conn *c) {
    if (strcmp(c->method, "GET") == 0 && strcmp(c->path, "/healthz") == 0) {
        send_simple(c, 200, "text/plain", "ok\n");
        return;
    }
    if (strcmp(c->method, "GET") == 0 && strcmp(c->path, "/metrics") == 0) {
        char body[256];
        snprintf(body, sizeof(body), "proxy_requests_total %llu\n",
                 (unsigned long long)g_requests_total);
        send_simple(c, 200, "text/plain; version=0.0.4", body);
        return;
    }
    if (strcmp(c->method, "POST") == 0 && strcmp(c->path, "/v1/chat/completions") == 0) {
        g_requests_total++;
        const char *body = c->req.data + c->req_header_len;
        size_t blen = c->req_content_length;
        c->is_stream = body_is_stream(body, blen);
        c->up_index = 0;
        start_connect(c);
        return;
    }
    send_simple(c, 404, "text/plain", "not found\n");
}

/* ------------------------------------------------------------------ upstream */

static int parse_upstream(const char *url, struct sockaddr_in *addr) {
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    const char *p = url;
    if (strncmp(p, "http://", 7) == 0) p += 7;
    char host[256];
    size_t i = 0;
    while (p[i] && p[i] != ':' && p[i] != '/' && i < sizeof(host) - 1) {
        host[i] = p[i];
        i++;
    }
    host[i] = 0;
    int port = 80;
    if (p[i] == ':') port = atoi(p + i + 1);
    addr->sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr->sin_addr) != 1) {
        struct hostent *he = gethostbyname(host);
        if (!he) return -1;
        memcpy(&addr->sin_addr, he->h_addr, he->h_length);
    }
    return 0;
}

static void start_connect(Conn *c) {
    if (c->up_index >= g_n_upstreams) {
        send_error(c, 502, "all upstreams failed");
        return;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        failover(c);
        return;
    }
    set_nonblocking(fd);
    struct sockaddr_in addr;
    if (parse_upstream(g_upstreams[c->up_index], &addr) != 0) {
        close(fd);
        failover(c);
        return;
    }
    c->up_fd = fd;
    conn_set(fd, c);
    c->up_connected = 0;
    c->up_headers_parsed = 0;
    c->up_header_len = 0;
    c->up_status = 0;
    c->up_chunked = 0;
    c->up_has_cl = 0;
    c->up_content_length = 0;
    c->up_body_received = 0;
    c->up_ttft_active = 0;
    buf_reset(&c->up_in);
    buf_reset(&c->up_out);
    struct epoll_event uev;
    uev.events = EPOLLOUT;
    uev.data.fd = fd;
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &uev);
    int r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (r == 0) {
        c->up_connected = 1;
        c->state = ST_SEND_REQUEST;
        buf_append(&c->up_out, c->req.data, c->req.len);
        update_events(c);
        flush_upstream(c);
    } else if (errno == EINPROGRESS) {
        c->state = ST_CONNECT;
        update_events(c);
    } else {
        close(fd);
        c->up_fd = -1;
        failover(c);
    }
}

static void failover(Conn *c) {
    if (c->first_byte_sent) return;
    close_upstream(c);
    c->up_index++;
    if (c->up_index < g_n_upstreams) {
        start_connect(c);
    } else {
        send_error(c, 502, "all upstreams failed");
    }
}

static void flush_upstream(Conn *c) {
    while (c->up_out.off < c->up_out.len) {
        ssize_t n = write(c->up_fd, c->up_out.data + c->up_out.off, c->up_out.len - c->up_out.off);
        if (n > 0) {
            c->up_out.off += n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            failover(c);
            return;
        }
    }
    if (c->up_out.off >= c->up_out.len) {
        buf_reset(&c->up_out);
        if (c->state == ST_SEND_REQUEST) c->state = ST_WAIT_HEADERS;
        update_events(c);
    }
}

static void start_ttft(Conn *c) {
    c->up_ttft_active = 1;
    c->up_ttft_deadline = now_ms() + g_ttft_ms;
}

static void cancel_ttft(Conn *c) {
    c->up_ttft_active = 0;
}

static void check_completion(Conn *c) {
    if (c->up_chunked) {
        if (find_sub(c->out.data, c->out.len, "\r\n0\r\n\r\n", 8)) {
            finish_response(c);
        }
    } else if (c->up_has_cl) {
        if (c->up_body_received >= c->up_content_length) {
            finish_response(c);
        }
    }
}

static void finish_response(Conn *c) {
    close_upstream(c);
    c->state = ST_DONE;
    c->close_after_flush = 1;
    update_events(c);
    if (c->out.off >= c->out.len) close_conn(c);
}

static void finish_client(Conn *c) {
    c->close_after_flush = 1;
    if (c->out.off >= c->out.len) {
        close_conn(c);
    } else {
        update_events(c);
    }
}

static void process_upstream(Conn *c) {
    if (!c->up_headers_parsed) {
        char *hdr_end = find_sub(c->up_in.data, c->up_in.len, "\r\n\r\n", 4);
        if (!hdr_end) return;
        size_t hlen = (size_t)(hdr_end + 4 - c->up_in.data);
        parse_upstream_headers(c, c->up_in.data, hlen);
        c->up_headers_parsed = 1;
        c->up_header_len = hlen;
        if (c->up_status >= 500 || c->up_status == 429) {
            failover(c);
            return;
        }
        if (c->is_stream) {
            c->state = ST_WAIT_FIRST_BODY;
            start_ttft(c);
        } else {
            size_t body_len = c->up_in.len - hlen;
            c->up_body_received += body_len;
            forward_to_client(c, c->up_in.data, c->up_in.len);
            c->state = ST_STREAM;
            buf_reset(&c->up_in);
            check_completion(c);
            return;
        }
    }
    if (c->state == ST_WAIT_FIRST_BODY) {
        if (c->up_in.len > c->up_header_len) {
            cancel_ttft(c);
            size_t body_len = c->up_in.len - c->up_header_len;
            c->up_body_received += body_len;
            forward_to_client(c, c->up_in.data, c->up_in.len);
            c->state = ST_STREAM;
            buf_reset(&c->up_in);
            check_completion(c);
        }
        return;
    }
    if (c->state == ST_STREAM) {
        if (c->up_in.len > 0) {
            c->up_body_received += c->up_in.len;
            forward_to_client(c, c->up_in.data, c->up_in.len);
            buf_reset(&c->up_in);
            check_completion(c);
        }
    }
}

static void handle_upstream_eof(Conn *c) {
    if (c->state == ST_WAIT_HEADERS || c->state == ST_WAIT_FIRST_BODY) {
        failover(c);
    } else if (c->state == ST_STREAM) {
        close_upstream(c);
        finish_client(c);
    } else {
        close_upstream(c);
    }
}

/* ------------------------------------------------------------------ event handlers */

static void on_client_readable(Conn *c) {
    if (c->state == ST_READ_REQUEST) {
        char buf[65536];
        ssize_t n = read(c->fd, buf, sizeof(buf));
        if (n > 0) {
            buf_append(&c->req, buf, n);
            try_complete_request(c);
        } else if (n == 0) {
            close_conn(c);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            close_conn(c);
        }
    } else {
        char buf[1024];
        ssize_t n = read(c->fd, buf, sizeof(buf));
        if (n == 0) {
            close_upstream(c);
            close_conn(c);
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            close_upstream(c);
            close_conn(c);
        }
    }
}

static void flush_client(Conn *c) {
    while (c->out.off < c->out.len) {
        ssize_t n = write(c->fd, c->out.data + c->out.off, c->out.len - c->out.off);
        if (n > 0) {
            c->out.off += n;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            close_conn(c);
            return;
        }
    }
    if (c->out.off >= c->out.len) {
        buf_reset(&c->out);
        if (c->close_after_flush) {
            close_conn(c);
        } else {
            update_events(c);
        }
    }
}

static void on_upstream_writable(Conn *c) {
    if (c->state == ST_CONNECT) {
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(c->up_fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err != 0) {
            failover(c);
            return;
        }
        c->up_connected = 1;
        c->state = ST_SEND_REQUEST;
        buf_append(&c->up_out, c->req.data, c->req.len);
        update_events(c);
        flush_upstream(c);
    } else if (c->state == ST_SEND_REQUEST) {
        flush_upstream(c);
    }
}

static void on_upstream_readable(Conn *c) {
    char buf[65536];
    ssize_t n = read(c->up_fd, buf, sizeof(buf));
    if (n > 0) {
        buf_append(&c->up_in, buf, n);
        process_upstream(c);
    } else if (n == 0) {
        handle_upstream_eof(c);
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        handle_upstream_eof(c);
    }
}

/* ------------------------------------------------------------------ accept */

static void accept_clients(void) {
    for (;;) {
        int cfd = accept(g_listen_fd, NULL, NULL);
        if (cfd < 0) break;
        set_nonblocking(cfd);
        Conn *c = calloc(1, sizeof(Conn));
        c->fd = cfd;
        c->up_fd = -1;
        c->state = ST_READ_REQUEST;
        conn_set(cfd, c);
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = cfd;
        epoll_ctl(g_epfd, EPOLL_CTL_ADD, cfd, &ev);
    }
}

/* ------------------------------------------------------------------ timers */

static int compute_timeout(void) {
    uint64_t now = now_ms();
    uint64_t min_deadline = UINT64_MAX;
    for (size_t fd = 0; fd < g_conns_cap; fd++) {
        Conn *c = g_conns[fd];
        if (c && c->up_ttft_active && c->state == ST_WAIT_FIRST_BODY) {
            if (c->up_ttft_deadline < min_deadline) min_deadline = c->up_ttft_deadline;
        }
    }
    if (min_deadline == UINT64_MAX) return -1;
    if (now >= min_deadline) return 0;
    uint64_t diff = min_deadline - now;
    if (diff > 1000) return 1000;
    return (int)diff;
}

static void check_ttft(void) {
    uint64_t now = now_ms();
    for (size_t fd = 0; fd < g_conns_cap; fd++) {
        Conn *c = g_conns[fd];
        if (c && c->up_ttft_active && c->state == ST_WAIT_FIRST_BODY && now >= c->up_ttft_deadline) {
            c->up_ttft_active = 0;
            failover(c);
        }
    }
}

/* ------------------------------------------------------------------ env */

static void parse_env(void) {
    const char *ttft = getenv("TTFT_TIMEOUT_MS");
    if (ttft) g_ttft_ms = atoi(ttft);
    const char *ups = getenv("UPSTREAMS");
    if (!ups) ups = "";
    char *copy = strdup(ups);
    char *save = NULL;
    char *tok = strtok_r(copy, ",", &save);
    while (tok && g_n_upstreams < MAX_UPSTREAMS) {
        g_upstreams[g_n_upstreams++] = strdup(tok);
        tok = strtok_r(NULL, ",", &save);
    }
    free(copy);
}

static int parse_listen_addr(const char *s, struct sockaddr_in *addr) {
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    if (!s) return -1;
    char host[256];
    size_t i = 0;
    while (s[i] && s[i] != ':' && i < sizeof(host) - 1) {
        host[i] = s[i];
        i++;
    }
    host[i] = 0;
    int port = 80;
    if (s[i] == ':') port = atoi(s + i + 1);
    addr->sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr->sin_addr) != 1) return -1;
    return 0;
}

/* ------------------------------------------------------------------ main */

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    parse_env();

    g_epfd = epoll_create1(0);
    if (g_epfd < 0) return 1;

    g_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_fd < 0) return 1;
    set_nonblocking(g_listen_fd);
    int one = 1;
    setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    if (parse_listen_addr(getenv("LISTEN_ADDR"), &addr) != 0) return 1;
    if (bind(g_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 1;
    if (listen(g_listen_fd, 1024) != 0) return 1;

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = g_listen_fd;
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, g_listen_fd, &ev);

    struct epoll_event events[MAX_EVENTS];
    for (;;) {
        int timeout = compute_timeout();
        int n = epoll_wait(g_epfd, events, MAX_EVENTS, timeout);
        check_ttft();
        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;
            uint32_t e = events[i].events;
            if (fd == g_listen_fd) {
                accept_clients();
                continue;
            }
            Conn *c = conn_get(fd);
            if (!c) continue;
            if (fd == c->fd) {
                if (e & (EPOLLIN | EPOLLHUP | EPOLLERR)) on_client_readable(c);
                if (!c->closed && (e & EPOLLOUT)) flush_client(c);
            } else if (fd == c->up_fd) {
                if (e & EPOLLOUT) on_upstream_writable(c);
                if (!c->closed && (e & (EPOLLIN | EPOLLHUP | EPOLLERR))) on_upstream_readable(c);
            }
            if (c->closed) free_conn(c);
        }
    }
    return 0;
}