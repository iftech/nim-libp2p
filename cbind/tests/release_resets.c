// Releasing a dialed stream without closing it resets the stream on the remote.
#include "../examples/common.h"

static const char *Proto = "/cbind/release/1.0.0";
static const int64_t ReadTimeoutMs = 5000;

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

static void on_read(int ec, const ReadResponse *reply, const char *em,
                    void *ud) {
  (void)reply;
  on_bool(ec, NULL, em, ud);
}

static LibP2PCtx *createNode(const char *label) {
  NimFfiStr addrSlot = nimffi_str("/ip4/127.0.0.1/tcp/0");
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.addrs.data = &addrSlot;
  cfg.addrs.len = 1;
  cfg.muxer = MUXER_TYPE_MPLEX;
  cfg.transport = TRANSPORT_TYPE_TCP;
  return await_create(&cfg, label);
}

static bool dialAndRelease(LibP2PCtx *client, const PeerInfoWaiter *pw) {
  NimFfiStr addrs[MAX_ADDRS];
  for (size_t i = 0; i < pw->naddrs; i++)
    addrs[i] = nimffi_str(pw->addrs[i]);
  DialRequest req = {
      nimffi_str(pw->peerId), nimffi_str(Proto), {addrs, pw->naddrs}, false, 0};
  DialWaiter dw;
  memset(&dw, 0, sizeof(dw));
  libp2p_ctx_dial(client, &req, on_dial, &dw);
  wait_done(&dw.done);
  if (dw.err_code != 0) {
    fprintf(stderr, "dial: %s\n", dw.err);
    return false;
  }

  // A reset before the remote negotiates stops the remote handler.
  wait_done(&g_have_stream);

  BoolWaiter bw;
  return AWAIT_BOOL(
      bw, libp2p_ctx_stream_release(client, dw.streamId, on_bool, &bw),
      "release");
}

static bool remoteSeesReset(LibP2PCtx *server) {
  BoolWaiter rw;
  memset(&rw, 0, sizeof(rw));
  StreamReadExactlyRequest req = {g_stream_id, 1, ReadTimeoutMs};
  libp2p_ctx_stream_read_exactly(server, &req, on_read, &rw);
  wait_done(&rw.done);
  if (rw.err_code == 0) {
    fprintf(stderr, "remote read: want an error, got a byte\n");
    return false;
  }

  // A read in flight ends with EOF, so only the write tells a reset from a
  // close.
  uint8_t byte = 0;
  NimFfiBytes data = {&byte, 1};
  StreamWriteRequest wreq = {g_stream_id, data};
  BoolWaiter ww;
  memset(&ww, 0, sizeof(ww));
  libp2p_ctx_stream_write(server, &wreq, on_bool, &ww);
  wait_done(&ww.done);
  if (ww.err_code == 0 || !strstr(ww.err, "Stream Reset!")) {
    fprintf(stderr, "remote write: want reset, got %d \"%s\"\n", ww.err_code,
            ww.err);
    return false;
  }
  printf("remote write: %s\n", ww.err);

  BoolWaiter bw;
  return AWAIT_BOOL(
      bw, libp2p_ctx_stream_release(server, g_stream_id, on_bool, &bw),
      "server release");
}

int main(void) {
  LibP2PCtx *server = createNode("server");
  LibP2PCtx *client = createNode("client");
  if (!server || !client) {
    libp2p_ctx_destroy(server);
    libp2p_ctx_destroy(client);
    return EXIT_FAILURE;
  }
  libp2p_ctx_add_on_incoming_stream_listener(server, onIncomingStream, NULL);

  bool ok = false;
  BoolWaiter bw;
  PeerInfoWaiter pw;
  if (!AWAIT_BOOL(
          bw,
          libp2p_ctx_mount_protocol(server, nimffi_str(Proto), on_bool, &bw),
          "mount_protocol") ||
      !AWAIT_BOOL(bw, libp2p_ctx_start(server, on_bool, &bw), "start server") ||
      !AWAIT_BOOL(bw, libp2p_ctx_start(client, on_bool, &bw), "start client") ||
      !await_peerinfo(server, &pw, "server peerinfo"))
    goto cleanup;

  ok = dialAndRelease(client, &pw) && remoteSeesReset(server);

cleanup:
  AWAIT_BOOL(bw, libp2p_ctx_stop(client, on_bool, &bw), "stop client");
  AWAIT_BOOL(bw, libp2p_ctx_stop(server, on_bool, &bw), "stop server");
  libp2p_ctx_destroy(client);
  libp2p_ctx_destroy(server);
  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
