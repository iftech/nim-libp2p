// Echo over a custom `/cbind/echo/1.0.0` protocol: a server node echoes the
// bytes it reads; a client node dials, sends a payload and verifies the echo.
// The generated bindings are asynchronous, so every call is wrapped with the
// blocking helpers in common.h. nim-ffi rejects reentrant calls (a method may
// not be invoked from a callback running on its dispatch thread) and its worker
// threads own the Nim GC state, so all calls are made from `main`: the
// incoming-stream handler only hands `main` the stream id, which it then
// serves inline.
#include "common.h"

static const char *EchoProto = "/cbind/echo/1.0.0";
static const int64_t EchoMaxSize = 4096;

// Single-slot hand-off from the incoming-stream event to main.
static atomic_int g_have_stream = 0;
static uint64_t g_stream_id = 0;

static void onIncomingStream(const IncomingStreamEvent *evt, void *ud) {
  (void)ud;
  g_stream_id = evt->streamId;
  atomic_store(&g_have_stream, 1);
}

typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  uint8_t data[4096];
  size_t len;
} ReadWaiter;

static void on_read(int ec, const ReadResponse *reply, const char *em,
                    void *ud) {
  ReadWaiter *w = (ReadWaiter *)ud;
  w->err_code = ec;
  if (reply && reply->data.data) {
    w->len =
        reply->data.len < sizeof(w->data) ? reply->data.len : sizeof(w->data);
    memcpy(w->data, reply->data.data, w->len);
  }
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

// Reads the request off the accepted stream, echoes it back and releases it.
static bool serveEcho(LibP2PCtx *server) {
  wait_done(&g_have_stream);
  uint64_t streamId = g_stream_id;
  atomic_store(&g_have_stream, 0);

  ReadWaiter rw;
  memset(&rw, 0, sizeof(rw));
  StreamReadLpRequest readReq = {streamId, EchoMaxSize};
  libp2p_ctx_stream_read_lp(server, &readReq, on_read, &rw);
  wait_done(&rw.done);
  if (rw.err_code != 0) {
    fprintf(stderr, "server read: %s\n", rw.err[0] ? rw.err : "unknown");
    return false;
  }

  BoolWaiter bw;
  NimFfiBytes payload = {rw.data, rw.len};
  StreamWriteRequest writeReq = {streamId, payload};
  bool ok = AWAIT_BOOL(
      bw, libp2p_ctx_stream_write_lp(server, &writeReq, on_bool, &bw),
      "server write");
  AWAIT_BOOL(bw, libp2p_ctx_stream_release(server, streamId, on_bool, &bw),
             "server release");
  return ok;
}

typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  uint64_t streamId;
} DialWaiter;

static void on_dial(int ec, const DialResponse *reply, const char *em,
                    void *ud) {
  DialWaiter *w = (DialWaiter *)ud;
  w->err_code = ec;
  if (reply)
    w->streamId = reply->streamId;
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

// One dial, write, echo and verify cycle. `dialReq` decides whether the stream
// rides an existing connection or dials the addrs itself.
static bool echoRoundTrip(LibP2PCtx *client, LibP2PCtx *server,
                          const DialRequest *dialReq, const char *sent) {
  DialWaiter dw;
  memset(&dw, 0, sizeof(dw));
  libp2p_ctx_dial(client, dialReq, on_dial, &dw);
  wait_done(&dw.done);
  if (dw.err_code != 0) {
    fprintf(stderr, "dial: %s\n", dw.err[0] ? dw.err : "unknown");
    return false;
  }
  uint64_t streamId = dw.streamId;

  printf("Client sending: %s\n", sent);
  BoolWaiter bw;
  NimFfiBytes sentBytes = {(uint8_t *)sent, strlen(sent)};
  StreamWriteRequest writeReq = {streamId, sentBytes};
  if (!AWAIT_BOOL(bw,
                  libp2p_ctx_stream_write_lp(client, &writeReq, on_bool, &bw),
                  "stream_write_lp"))
    return false;

  // The server side runs on this thread too: read the request and echo it back
  // before the client reads the reply.
  if (!serveEcho(server))
    return false;

  ReadWaiter rw;
  memset(&rw, 0, sizeof(rw));
  StreamReadLpRequest readReq = {streamId, EchoMaxSize};
  libp2p_ctx_stream_read_lp(client, &readReq, on_read, &rw);
  wait_done(&rw.done);
  if (rw.err_code != 0) {
    fprintf(stderr, "stream_read_lp: %s\n", rw.err[0] ? rw.err : "unknown");
    return false;
  }
  printf("Client received: %.*s\n", (int)rw.len, (const char *)rw.data);

  bool matched = rw.len == strlen(sent) && memcmp(rw.data, sent, rw.len) == 0;
  if (!matched)
    fprintf(stderr, "Error: echoed payload did not match\n");

  AWAIT_BOOL(bw,
             libp2p_ctx_stream_close_with_eof(client, streamId, on_bool, &bw),
             "stream_close_with_eof");
  AWAIT_BOOL(bw, libp2p_ctx_stream_release(client, streamId, on_bool, &bw),
             "stream_release");
  return matched;
}

// Parks a server handler on an unreleased stream; stop must still return.
static bool openUnreleased(LibP2PCtx *client, const DialRequest *dialReq) {
  DialWaiter dw;
  memset(&dw, 0, sizeof(dw));
  libp2p_ctx_dial(client, dialReq, on_dial, &dw);
  wait_done(&dw.done);
  if (dw.err_code != 0) {
    fprintf(stderr, "dial unreleased: %s\n", dw.err[0] ? dw.err : "unknown");
    return false;
  }
  wait_done(&g_have_stream);
  atomic_store(&g_have_stream, 0);
  return true;
}

static LibP2PCtx *createNode(const char *listenAddr, const char *label) {
  NimFfiStr addrSlot = nimffi_str(listenAddr);
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.addrs.data = &addrSlot;
  cfg.addrs.len = 1;
  cfg.muxer = MUXER_TYPE_MPLEX;
  cfg.transport = TRANSPORT_TYPE_TCP;
  return await_create(&cfg, label);
}

int main(void) {
  LibP2PCtx *server = createNode("/ip4/127.0.0.1/tcp/5013", "server");
  if (!server)
    return 1;

  // Mount before start so peers learn about the protocol during identify.
  libp2p_ctx_add_on_incoming_stream_listener(server, onIncomingStream, NULL);

  BoolWaiter bw;
  if (!AWAIT_BOOL(bw,
                  libp2p_ctx_mount_protocol(server, nimffi_str(EchoProto),
                                            on_bool, &bw),
                  "mount_protocol") ||
      !AWAIT_BOOL(bw, libp2p_ctx_start(server, on_bool, &bw), "start server")) {
    libp2p_ctx_destroy(server);
    return 1;
  }

  PeerInfoWaiter pw;
  if (!await_peerinfo(server, &pw, "peerinfo")) {
    libp2p_ctx_destroy(server);
    return 1;
  }
  printf("Echo server started: %s\n", pw.peerId);
  for (size_t i = 0; i < pw.naddrs; i++)
    printf("  %s\n", pw.addrs[i]);

  LibP2PCtx *client = createNode("/ip4/127.0.0.1/tcp/0", "client");
  if (!client) {
    libp2p_ctx_destroy(server);
    return 1;
  }

  int status = 1;
  if (!AWAIT_BOOL(bw, libp2p_ctx_start(client, on_bool, &bw), "start client"))
    goto cleanup;

  // Addrs on the dial connect the peer and open the stream in one call.
  NimFfiStr dialAddrs[MAX_ADDRS];
  for (size_t i = 0; i < pw.naddrs; i++)
    dialAddrs[i] = nimffi_str(pw.addrs[i]);
  DialRequest dialWithAddrs = {nimffi_str(pw.peerId),
                               nimffi_str(EchoProto),
                               {dialAddrs, pw.naddrs},
                               false,
                               0};
  if (!echoRoundTrip(client, server, &dialWithAddrs, "hello from cbind echo"))
    goto cleanup;

  // Without addrs the dial opens a second stream over that same connection.
  DialRequest dialConnected = {
      nimffi_str(pw.peerId), nimffi_str(EchoProto), {NULL, 0}, false, 0};
  if (!echoRoundTrip(client, server, &dialConnected, "hello again"))
    goto cleanup;

  if (!openUnreleased(client, &dialConnected))
    goto cleanup;

  status = 0;

cleanup:
  AWAIT_BOOL(bw, libp2p_ctx_stop(client, on_bool, &bw), "stop client");
  AWAIT_BOOL(bw, libp2p_ctx_stop(server, on_bool, &bw), "stop server");
  libp2p_ctx_destroy(client);
  libp2p_ctx_destroy(server);
  return status;
}
