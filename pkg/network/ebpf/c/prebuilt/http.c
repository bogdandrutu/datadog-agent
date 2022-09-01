#include "kconfig.h"
#include "tracer.h"
#include "bpf_helpers.h"
#include "ip.h"
#include "ipv6.h"
#include "http.h"
#include "https.h"
#include "http-buffer.h"
#include "sockfd.h"
#include "tags-types.h"
#include "sock.h"
#include "port_range.h"
#include "go-tls-types.h"
#include "go-tls-goid.h"
#include "go-tls-location.h"
#include "go-tls-conn.h"

#define HTTPS_PORT 443
#define SO_SUFFIX_SIZE 3

static __always_inline void read_into_buffer_skb(char *buffer, struct __sk_buff* skb, skb_info_t *info) {
    u64 offset = (u64)info->data_off;

#define BLK_SIZE (4)
    const u32 iter = HTTP_BUFFER_SIZE / BLK_SIZE;
    const u32 len = HTTP_BUFFER_SIZE < (skb->len - (u32)offset) ? (u32)offset + HTTP_BUFFER_SIZE : skb->len;

    unsigned i = 0;

#pragma unroll(HTTP_BUFFER_SIZE / BLK_SIZE)
    for (; i < iter; i++) {
        if (offset + BLK_SIZE - 1 >= len) { break; }

        // There was a bug in the bpf translatter that was incorrectly clobbering r2 register,
        // which led to erasing r1 value in that case:
        //      0:  r6 = r1
        //      1:  r1 = 12
        //      2:  r0 = *(u16 *)skb[r1]
        // https://github.com/torvalds/linux/commit/e6a18d36118bea3bf497c9df4d9988b6df120689
        //
        // To prevent the compiler from using the r1 register in the `load_*` functions, we need
        // to fake using it, so that it increases the chance for the compiler not using it.
        asm volatile("":::"r1");
        *(u32 *)buffer = __builtin_bswap32(load_word(skb, offset));
        asm volatile("":::"r1");

        offset += BLK_SIZE;
        buffer += BLK_SIZE;
    }

    // This part is very hard to write in a loop and unroll it.
    // Indeed, mostly because of 4.4 verifier, we want to make sure the offset into the buffer is not
    // stored on the stack, so that the verifier is able to verify that we're not doing out-of-bound on
    // the stack.
    // Basically, we should get a register from the code block above containing an fp relative address. As
    // we are doing `buffer[0]` here, there is not dynamic computation on that said register after this,
    // and thus the verifier is able to ensure that we are in-bound.
    if (offset + 2 < len) {
        asm volatile("":::"r1");
        *(u16 *)(&buffer[0]) = __builtin_bswap16(load_half(skb, offset));
        asm volatile("":::"r1");
        *(&buffer[2]) = load_byte(skb, offset + 2);
        asm volatile("":::"r1");
    } else if (offset + 1 < len) {
        asm volatile("":::"r1");
        *(u16 *)(&buffer[0]) = __builtin_bswap16(load_half(skb, offset));
        asm volatile("":::"r1");
    } else if (offset < len) {
        asm volatile("":::"r1");
        *(&buffer[0]) = load_byte(skb, offset);
        asm volatile("":::"r1");
    }
}

// This entry point is needed to bypass a memory limit on socket filters
// See: https://datadoghq.atlassian.net/wiki/spaces/NET/pages/2326855913/HTTP#Known-issues
SEC("socket/http_filter_entry")
int socket__http_filter_entry(struct __sk_buff *skb) {
    bpf_tail_call_compat(skb, &http_progs, HTTP_PROG);
    return 0;
}


SEC("socket/http_filter")
int socket__http_filter(struct __sk_buff* skb) {
    skb_info_t skb_info;
    http_transaction_t http;
    __builtin_memset(&http, 0, sizeof(http));

    if (!read_conn_tuple_skb(skb, &skb_info, &http.tup)) {
        return 0;
    }

    // If the socket is for https and it is finishing,
    // make sure we pass it on to `http_process` to ensure that any ongoing transaction is flushed.
    // Otherwise, don't bother to inspect packet contents
    // when there is no chance we're dealing with plain HTTP (or a finishing HTTPS socket)
    if (!(http.tup.metadata&CONN_TYPE_TCP)) {
        return 0;
    }
    if ((http.tup.sport == HTTPS_PORT || http.tup.dport == HTTPS_PORT) && !(skb_info.tcp_flags & TCPHDR_FIN)) {
        return 0;
    }

    // src_port represents the source port number *before* normalization
    // for more context please refer to http-types.h comment on `owned_by_src_port` field
    http.owned_by_src_port = http.tup.sport;
    normalize_tuple(&http.tup);

    read_into_buffer_skb((char *)http.request_fragment, skb, &skb_info);
    http_process(&http, &skb_info, NO_TAGS);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs* ctx) {
    // map connection tuple during SSL_do_handshake(ctx)
    init_ssl_sock_from_do_handshake((struct sock*)PT_REGS_PARM1(ctx));
    return 0;
}

SEC("kretprobe/security_sock_rcv_skb")
int kretprobe__security_sock_rcv_skb(struct pt_regs* ctx) {
    // send batch completion notification to userspace
    // because perf events can't be sent from socket filter programs
    http_notify_batch(ctx);
    return 0;
}


SEC("uprobe/SSL_do_handshake")
int uprobe__SSL_do_handshake(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    void *ssl_ctx = (void *)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&ssl_ctx_by_pid_tgid, &pid_tgid, &ssl_ctx, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_do_handshake")
int uretprobe__SSL_do_handshake(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ssl_ctx_by_pid_tgid, &pid_tgid);
    return 0;
}

SEC("uprobe/SSL_connect")
int uprobe__SSL_connect(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    void *ssl_ctx = (void *)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&ssl_ctx_by_pid_tgid, &pid_tgid, &ssl_ctx, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_connect")
int uretprobe__SSL_connect(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ssl_ctx_by_pid_tgid, &pid_tgid);
    return 0;
}

// this uprobe is essentially creating an index mapping a SSL context to a conn_tuple_t
SEC("uprobe/SSL_set_fd")
int uprobe__SSL_set_fd(struct pt_regs* ctx) {
    void *ssl_ctx = (void *)PT_REGS_PARM1(ctx);
    u32 socket_fd = (u32)PT_REGS_PARM2(ctx);
    init_ssl_sock(ssl_ctx, socket_fd);
    return 0;
}

SEC("uprobe/BIO_new_socket")
int uprobe__BIO_new_socket(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 socket_fd = (u32)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&bio_new_socket_args, &pid_tgid, &socket_fd, BPF_ANY);
    return 0;
}

SEC("uretprobe/BIO_new_socket")
int uretprobe__BIO_new_socket(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 *socket_fd = bpf_map_lookup_elem(&bio_new_socket_args, &pid_tgid);
    if (socket_fd == NULL) {
        return 0;
    }

    void *bio = (void *)PT_REGS_RC(ctx);
    if (bio == NULL) {
        goto cleanup;
    }
    u32 fd = *socket_fd; // copy map value into stack (required by older Kernels)
    bpf_map_update_elem(&fd_by_ssl_bio, &bio, &fd, BPF_ANY);
cleanup:
    bpf_map_delete_elem(&bio_new_socket_args, &pid_tgid);
    return 0;
}

SEC("uprobe/SSL_set_bio")
int uprobe__SSL_set_bio(struct pt_regs* ctx) {
    void *ssl_ctx = (void *)PT_REGS_PARM1(ctx);
    void *bio = (void *)PT_REGS_PARM2(ctx);
    u32 *socket_fd = bpf_map_lookup_elem(&fd_by_ssl_bio, &bio);
    if (socket_fd == NULL)  {
        return 0;
    }
    init_ssl_sock(ssl_ctx, *socket_fd);
    bpf_map_delete_elem(&fd_by_ssl_bio, &bio);
    return 0;
}

SEC("uprobe/SSL_read")
int uprobe__SSL_read(struct pt_regs* ctx) {
    ssl_read_args_t args = {0};
    args.ctx = (void *)PT_REGS_PARM1(ctx);
    args.buf = (void *)PT_REGS_PARM2(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int uretprobe__SSL_read(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    ssl_read_args_t *args = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (args == NULL) {
        return 0;
    }

    void *ssl_ctx = args->ctx;
    conn_tuple_t *t = tup_from_ssl_ctx(ssl_ctx, pid_tgid);
    if (t == NULL) {
        goto cleanup;
    }

    u32 len = (u32)PT_REGS_RC(ctx);
    https_process(t, args->buf, len, LIBSSL);
cleanup:
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);
    return 0;
}

SEC("uprobe/SSL_write")
int uprobe__SSL_write(struct pt_regs* ctx) {
    void *ssl_ctx = (void *)PT_REGS_PARM1(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    conn_tuple_t *t = tup_from_ssl_ctx(ssl_ctx, pid_tgid);
    if (t == NULL) {
        return 0;
    }

    void *ssl_buffer = (void *)PT_REGS_PARM2(ctx);
    size_t len = (size_t)PT_REGS_PARM3(ctx);
    https_process(t, ssl_buffer, len, LIBSSL);
    return 0;
}

SEC("uprobe/SSL_shutdown")
int uprobe__SSL_shutdown(struct pt_regs* ctx) {
    void *ssl_ctx = (void *)PT_REGS_PARM1(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    conn_tuple_t *t = tup_from_ssl_ctx(ssl_ctx, pid_tgid);
    if (t == NULL) {
        return 0;
    }

    https_finish(t);
    bpf_map_delete_elem(&ssl_sock_by_ctx, &ssl_ctx);
    return 0;
}

SEC("uprobe/gnutls_handshake")
int uprobe__gnutls_handshake(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    void *ssl_ctx = (void *)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&ssl_ctx_by_pid_tgid, &pid_tgid, &ssl_ctx, BPF_ANY);
    return 0;
}

SEC("uretprobe/gnutls_handshake")
int uretprobe__gnutls_handshake(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&ssl_ctx_by_pid_tgid, &pid_tgid);
    return 0;
}

// void gnutls_transport_set_int (gnutls_session_t session, int fd)
// Note: this function is implemented as a macro in gnutls
// that calls gnutls_transport_set_int2, so no uprobe is needed

// void gnutls_transport_set_int2 (gnutls_session_t session, int recv_fd, int send_fd)
SEC("uprobe/gnutls_transport_set_int2")
int uprobe__gnutls_transport_set_int2(struct pt_regs *ctx) {
    void *ssl_session = (void *)PT_REGS_PARM1(ctx);
    // Use the recv_fd and ignore the send_fd;
    // in most real-world scenarios, they are the same.
    int recv_fd = (int)PT_REGS_PARM2(ctx);
    log_debug("gnutls_transport_set_int2: ctx=%llx fd=%d\n", ssl_session, recv_fd);

    init_ssl_sock(ssl_session, (u32)recv_fd);
    return 0;
}

// void gnutls_transport_set_ptr (gnutls_session_t session, gnutls_transport_ptr_t ptr)
// "In berkeley style sockets this function will set the connection descriptor."
SEC("uprobe/gnutls_transport_set_ptr")
int uprobe__gnutls_transport_set_ptr(struct pt_regs *ctx) {
    void *ssl_session = (void *)PT_REGS_PARM1(ctx);
    // This is a void*, but it might contain the socket fd cast as a pointer.
    int fd = (int)PT_REGS_PARM2(ctx);
    log_debug("gnutls_transport_set_ptr: ctx=%llx fd=%d\n", ssl_session, fd);

    init_ssl_sock(ssl_session, (u32)fd);
    return 0;
}

// void gnutls_transport_set_ptr2 (gnutls_session_t session, gnutls_transport_ptr_t recv_ptr, gnutls_transport_ptr_t send_ptr)
// "In berkeley style sockets this function will set the connection descriptor."
SEC("uprobe/gnutls_transport_set_ptr2")
int uprobe__gnutls_transport_set_ptr2(struct pt_regs *ctx) {
    void *ssl_session = (void *)PT_REGS_PARM1(ctx);
    // Use the recv_ptr and ignore the send_ptr;
    // in most real-world scenarios, they are the same.
    // This is a void*, but it might contain the socket fd cast as a pointer.
    int recv_fd = (int)PT_REGS_PARM2(ctx);
    log_debug("gnutls_transport_set_ptr2: ctx=%llx fd=%d\n", ssl_session, recv_fd);

    init_ssl_sock(ssl_session, (u32)recv_fd);
    return 0;
}

// ssize_t gnutls_record_recv (gnutls_session_t session, void * data, size_t data_size)
SEC("uprobe/gnutls_record_recv")
int uprobe__gnutls_record_recv(struct pt_regs *ctx) {
    void *ssl_session = (void *)PT_REGS_PARM1(ctx);
    void *data = (void *)PT_REGS_PARM2(ctx);

    // Re-use the map for SSL_read
    ssl_read_args_t args = {
        .ctx = ssl_session,
        .buf = data,
    };
    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("gnutls_record_recv: pid=%llu ctx=%llx\n", pid_tgid, ssl_session);
    bpf_map_update_elem(&ssl_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// ssize_t gnutls_record_recv (gnutls_session_t session, void * data, size_t data_size)
SEC("uretprobe/gnutls_record_recv")
int uretprobe__gnutls_record_recv(struct pt_regs *ctx) {
    ssize_t read_len = (ssize_t)PT_REGS_RC(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    // Re-use the map for SSL_read
    ssl_read_args_t *args = bpf_map_lookup_elem(&ssl_read_args, &pid_tgid);
    if (args == NULL) {
        return 0;
    }

    void *ssl_session = args->ctx;
    log_debug("uret/gnutls_record_recv: pid=%llu ctx=%llx\n", pid_tgid, ssl_session);
    conn_tuple_t *t = tup_from_ssl_ctx(ssl_session, pid_tgid);
    if (t == NULL) {
        goto cleanup;
    }

    https_process(t, args->buf, read_len, LIBGNUTLS);
cleanup:
    bpf_map_delete_elem(&ssl_read_args, &pid_tgid);
    return 0;
}

// ssize_t gnutls_record_send (gnutls_session_t session, const void * data, size_t data_size)
SEC("uprobe/gnutls_record_send")
int uprobe__gnutls_record_send(struct pt_regs *ctx) {
    void *ssl_session = (void *)PT_REGS_PARM1(ctx);
    void *data = (void *)PT_REGS_PARM2(ctx);
    size_t data_size = (size_t)PT_REGS_PARM3(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("gnutls_record_send: pid=%llu ctx=%llx\n", pid_tgid, ssl_session);
    conn_tuple_t *t = tup_from_ssl_ctx(ssl_session, pid_tgid);
    if (t == NULL) {
        return 0;
    }

    https_process(t, data, data_size, LIBGNUTLS);
    return 0;
}

static __always_inline void gnutls_goodbye(void *ssl_session) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    log_debug("gnutls_goodbye: pid=%llu ctx=%llx\n", pid_tgid, ssl_session);
    conn_tuple_t *t = tup_from_ssl_ctx(ssl_session, pid_tgid);
    if (t == NULL) {
        return;
    }

    https_finish(t);
    bpf_map_delete_elem(&ssl_sock_by_ctx, &ssl_session);
}

// int gnutls_bye (gnutls_session_t session, gnutls_close_request_t how)
SEC("uprobe/gnutls_bye")
int uprobe__gnutls_bye(struct pt_regs *ctx) {
    void *ssl_session = (void *)PT_REGS_PARM1(ctx);
    gnutls_goodbye(ssl_session);
    return 0;
}

// void gnutls_deinit (gnutls_session_t session)
SEC("uprobe/gnutls_deinit")
int uprobe__gnutls_deinit(struct pt_regs *ctx) {
    void *ssl_session = (void *)PT_REGS_PARM1(ctx);
    gnutls_goodbye(ssl_session);
    return 0;
}

static __always_inline int fill_path_safe(lib_path_t *path, char *path_argument) {
#pragma unroll
    for (int i = 0; i < LIB_PATH_MAX_SIZE; i++) {
        bpf_probe_read_user(&path->buf[i], 1, &path_argument[i]);
        if (path->buf[i] == 0) {
            path->len = i;
            break;
        }
    }
    return 0;
}

static __always_inline int do_sys_open_helper_enter(struct pt_regs* ctx) {
    char *path_argument = (char *)PT_REGS_PARM2(ctx);
    lib_path_t path = {0};
    if (bpf_probe_read_user(path.buf, sizeof(path.buf), path_argument) >= 0) {
// Find the null character and clean up the garbage following it
#pragma unroll
        for (int i = 0; i < LIB_PATH_MAX_SIZE; i++) {
            if (path.len) {
                path.buf[i] = 0;
            } else if (path.buf[i] == 0) {
                path.len = i;
            }
        }
    } else {
        fill_path_safe(&path, path_argument);
    }

    // Bail out if the path size is larger than our buffer
    if (!path.len) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    path.pid = pid_tgid >> 32;
    bpf_map_update_elem(&open_at_args, &pid_tgid, &path, BPF_ANY);
    return 0;
}

SEC("kprobe/do_sys_open")
int kprobe__do_sys_open(struct pt_regs* ctx) {
    return do_sys_open_helper_enter(ctx);
}

SEC("kprobe/do_sys_openat2")
int kprobe__do_sys_openat2(struct pt_regs* ctx) {
    return do_sys_open_helper_enter(ctx);
}

static __always_inline int do_sys_open_helper_exit(struct pt_regs* ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // If file couldn't be opened, bail out
    if ((long)PT_REGS_RC(ctx) < 0) {
        goto cleanup;
    }

    lib_path_t *path = bpf_map_lookup_elem(&open_at_args, &pid_tgid);
    if (path == NULL) {
        return 0;
    }

    // Detect whether the file being opened is a shared library
    bool is_shared_library = false;
#pragma unroll
    for (int i = 0; i < LIB_PATH_MAX_SIZE - SO_SUFFIX_SIZE; i++) {
        if (path->buf[i] == '.' && path->buf[i+1] == 's' && path->buf[i+2] == 'o') {
            is_shared_library = true;
            break;
        }
    }

    if (!is_shared_library) {
        goto cleanup;
    }

    // Copy map value into eBPF stack
    lib_path_t lib_path;
    __builtin_memcpy(&lib_path, path, sizeof(lib_path));

    u32 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(ctx, &shared_libraries, cpu, &lib_path, sizeof(lib_path));
cleanup:
    bpf_map_delete_elem(&open_at_args, &pid_tgid);
    return 0;
}

SEC("kretprobe/do_sys_open")
int kretprobe__do_sys_open(struct pt_regs* ctx) {
    return do_sys_open_helper_exit(ctx);
}

SEC("kretprobe/do_sys_openat2")
int kretprobe__do_sys_openat2(struct pt_regs* ctx) {
    return do_sys_open_helper_exit(ctx);
}

// This number will be interpreted by elf-loader to set the current running kernel version
__u32 _version SEC("version") = 0xFFFFFFFE; // NOLINT(bugprone-reserved-identifier)

char _license[] SEC("license") = "GPL"; // NOLINT(bugprone-reserved-identifier)

// GO TLS PROBES

static __always_inline tls_probe_data_t* get_probe_data(uint32_t key) {
	return bpf_map_lookup_elem(&probe_data, &key);
}

// func (c *Conn) Write(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Write")
int uprobe__crypto_tls_Conn_Write(struct pt_regs *ctx) {
	log_debug("##### WRITE\n");

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 pid = pid_tgid >> 32;

	tls_probe_data_t* pd = get_probe_data(pid);
	if (pd == NULL)
		return 1;

	void* conn_pointer = NULL;
	if (read_location(ctx, &pd->write_conn_pointer, sizeof(conn_pointer), &conn_pointer)) {
		return 1;
	}

	void* b_data = NULL;
	if (read_location(ctx, &pd->write_buffer.ptr, sizeof(b_data), &b_data)) {
		return 1;
	}
	uint64_t b_len = 0;
	if (read_location(ctx, &pd->write_buffer.len, sizeof(b_len), &b_len)) {
		return 1;
	}

	conn_tuple_t* t = conn_tup_from_tls_conn(pd, conn_pointer, pid_tgid);
	if (t == NULL) {
		return 1;
	}

    https_process(t, b_data, b_len, GO);
    return 0;
}

// func (c *Conn) Read(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Read")
int uprobe__crypto_tls_Conn_Read(struct pt_regs *ctx) {
    log_debug("##### READ\n");

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
	tls_probe_data_t* pd = get_probe_data(pid);
	if (pd == NULL)
		return 1;

	// Read the TGID and goroutine ID to make the partial call key
	read_partial_call_key_t call_key = {0};
	call_key.tgid = pid_tgid >> 32;
	if (read_goroutine_id(ctx, &pd->goroutine_id, &call_key.goroutine_id)) {
		return 1;
	}

	// Read the parameters to make the partial call data
	// (since the parameters might not be live by the time the return probe is hit).
	read_partial_call_data_t call_data = {0};
	if (read_location(ctx, &pd->read_conn_pointer, sizeof(call_data.conn_pointer), &call_data.conn_pointer)) {
		return 1;
	}
	if (read_location(ctx, &pd->read_buffer.ptr, sizeof(call_data.b_data), &call_data.b_data)) {
		return 1;
	}

	bpf_map_update_elem(&read_partial_calls, &call_key, &call_data, BPF_ANY);

	return 0;
}

// func (c *Conn) Read(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Read/return")
int uprobe__crypto_tls_Conn_Read__return(struct pt_regs *ctx) {
	log_debug("##### READ RETURN\n");
	u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
	tls_probe_data_t* pd = get_probe_data(pid);
	if (pd == NULL)
		return 1;

	// Read the TGID and goroutine ID to make the partial call key
	read_partial_call_key_t call_key = {0};
	call_key.tgid = pid;

	if (read_goroutine_id(ctx, &pd->goroutine_id, &call_key.goroutine_id)) {
		return 1;
	}

	read_partial_call_data_t* call_data_ptr = bpf_map_lookup_elem(&read_partial_calls, &call_key);
	if (call_data_ptr == NULL) {
		return 1;
	}
	read_partial_call_data_t call_data = *call_data_ptr;
    bpf_map_delete_elem(&read_partial_calls, &call_key);

	uint64_t bytes_read = 0;
	if (read_location(ctx, &pd->read_return_bytes, sizeof(bytes_read), &bytes_read)) {
		return 1;
	}

	conn_tuple_t* t = conn_tup_from_tls_conn(pd, (void*) call_data.conn_pointer, pid_tgid);
	if (t == NULL) {
		return 1;
	}

	// The error return value of Read isn't useful here
	// unless we can determine whether it is equal to io.EOF
	// (and if so, treat it like there's no error at all),
	// and I didn't find a straightforward way of doing this.

    https_process(t, (void*) call_data.b_data, bytes_read, GO);

	return 0;
}

// func (c *Conn) Close(b []byte) (int, error)
SEC("uprobe/crypto/tls.(*Conn).Close")
int uprobe__crypto_tls_Conn_Close(struct pt_regs *ctx) {
    log_debug("##### CLOSE\n");
	u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = pid_tgid >> 32;
	tls_probe_data_t* pd = get_probe_data(pid);
	if (pd == NULL)
		return 1;

	void* conn_pointer = NULL;
	if (read_location(ctx, &pd->close_conn_pointer, sizeof(conn_pointer), &conn_pointer)) {
		return 1;
	}

	conn_tuple_t* t = conn_tup_from_tls_conn(pd, conn_pointer, pid_tgid);
	if (t == NULL) {
		return 1;
	}

    char buffer[100];
    __builtin_memset(buffer, 0, sizeof(buffer));

    https_finish(t);

	// Clear the element in the map since this connection is closed
    bpf_map_delete_elem(&conn_tup_by_tls_conn, &conn_pointer);

    return 0;
}

static __always_inline void* get_tls_base(struct task_struct* task) {
    u32 key = 0;
    struct thread_struct *t = bpf_map_lookup_elem(&task_thread, &key);
    if (t == NULL) {
            return (void *) 0;
    }
    if (bpf_probe_read(t, sizeof(struct thread_struct), &task->thread) < 0)
            return NULL;

    #if defined(__x86_64__)
        #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
            return (void*) t->fs;
        #else
            return (void*) t->fsbase;
        #endif
    #elif defined(__aarch64__)
        #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
            return (void*) t->tp_value;
        #else
            return (void*) t->uw.tp_value;
        #endif
    #else
        #error "Unsupported platform"
    #endif
}


