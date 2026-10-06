// Kademlia DHT: two TCP nodes form a DHT (a server, and a client that lists the
// server as its bootstrap node), then round-trip a value and a provider record
// over the wire. The generated bindings are asynchronous, so every call is
// wrapped with the blocking helpers in common.h.
//
// The client learns the server through its `bootstrapNodes` config: at
// construction the DHT inserts each bootstrap peer (with its addresses) into
// the routing table, so the client can reach the server without any prior
// lookup. All DHT queries here originate at the client and travel to the
// server, which is why only the client needs to know the server.
#include "common.h"

// A key is just bytes for the DHT; the value is stored and fetched verbatim.
static const char *ValueKey = "/cbind/kad/demo-key";
static const char *ValueData = "hello kademlia";

// libp2p_static_create_cid returns the CID string, so it needs its own waiter.
typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  char cid[256];
} CidWaiter;

static void on_cid(int ec, const NimFfiStr *reply, const char *em, void *ud) {
  CidWaiter *w = (CidWaiter *)ud;
  w->err_code = ec;
  if (reply && reply->data)
    snprintf(w->cid, sizeof(w->cid), "%.*s", (int)reply->len, reply->data);
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

// kad_get_value replies with a ReadResponse carrying the stored bytes.
typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  uint8_t data[512];
  size_t len;
} ValueWaiter;

static void on_value(int ec, const ReadResponse *reply, const char *em,
                     void *ud) {
  ValueWaiter *w = (ValueWaiter *)ud;
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

// kad_get_providers replies with the peers that announced the CID.
#define MAX_PROVIDERS 8
typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  char peerIds[MAX_PROVIDERS][128];
  size_t n;
} ProvidersWaiter;

static void on_providers(int ec, const ProvidersResponse *reply, const char *em,
                         void *ud) {
  ProvidersWaiter *w = (ProvidersWaiter *)ud;
  w->err_code = ec;
  if (reply) {
    w->n = reply->providers.len < MAX_PROVIDERS ? reply->providers.len
                                                : MAX_PROVIDERS;
    for (size_t i = 0; i < w->n; i++)
      if (reply->providers.data[i].peerId.data)
        snprintf(w->peerIds[i], sizeof(w->peerIds[i]), "%s",
                 reply->providers.data[i].peerId.data);
  }
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

// Builds a kad-dht node. `boot` is NULL for the server (no bootstrap peers) or
// the server's PeerInfo for the client, whose DHT then knows how to reach it.
static LibP2PCtx *kadNode(const char *listenAddr, const char *label,
                          const PeerInfoWaiter *boot) {
  NimFfiStr addrSlot = nimffi_str(listenAddr);
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.mountKad = true;
  cfg.addrs.data = &addrSlot;
  cfg.addrs.len = 1;
  cfg.muxer = MUXER_TYPE_MPLEX;
  cfg.transport = TRANSPORT_TYPE_TCP;

  NimFfiStr bootAddrs[MAX_ADDRS];
  BootstrapNode bootNode;
  if (boot) {
    for (size_t i = 0; i < boot->naddrs; i++)
      bootAddrs[i] = nimffi_str(boot->addrs[i]);
    bootNode.peerId = nimffi_str(boot->peerId);
    bootNode.multiaddrs.data = bootAddrs;
    bootNode.multiaddrs.len = boot->naddrs;
    cfg.bootstrapNodes.data = &bootNode;
    cfg.bootstrapNodes.len = 1;
  }
  // await_create only reads cfg while encoding, so the stack-local bootstrap
  // views above stay valid for the whole call.
  return await_create(&cfg, label);
}

int main(void) {
  int status = 1;
  BoolWaiter bw;
  PeerInfoWaiter serverInfo;

  LibP2PCtx *server = kadNode("/ip4/127.0.0.1/tcp/5031", "server", NULL);
  if (!server)
    return 1;
  if (!AWAIT_BOOL(bw, libp2p_ctx_start(server, on_bool, &bw), "start server"))
    goto cleanup_server;
  if (!await_peerinfo(server, &serverInfo, "server peerinfo"))
    goto cleanup_server;
  printf("Server: %s\n", serverInfo.peerId);

  LibP2PCtx *client = kadNode("/ip4/127.0.0.1/tcp/5032", "client", &serverInfo);
  if (!client)
    goto cleanup_server;
  if (!AWAIT_BOOL(bw, libp2p_ctx_start(client, on_bool, &bw), "start client") ||
      !await_connect(client, &serverInfo))
    goto cleanup_client;
  if (!AWAIT_BOOL(bw, libp2p_ctx_kad_wait_bootstrap(client, 5000, on_bool, &bw),
                  "wait bootstrap"))
    goto cleanup_client;

  // ── Value round-trip: server stores, client fetches over the DHT ──────────
  NimFfiBytes key = {(uint8_t *)ValueKey, strlen(ValueKey)};
  NimFfiBytes value = {(uint8_t *)ValueData, strlen(ValueData)};
  KadPutValueRequest putReq = {key, value};
  if (!AWAIT_BOOL(bw, libp2p_ctx_kad_put_value(server, &putReq, on_bool, &bw),
                  "put_value"))
    goto cleanup_client;
  printf("Server stored %zu bytes under '%s'\n", value.len, ValueKey);

  ValueWaiter vw;
  memset(&vw, 0, sizeof(vw));
  // quorum 1: this two-node DHT has a single holder (the server), so one valid
  // response is enough. A negative value would ask for the default quorum (5),
  // which this topology can never reach; 0 is rejected by the binding.
  KadGetValueRequest getReq = {key, 1};
  libp2p_ctx_kad_get_value(client, &getReq, on_value, &vw);
  wait_done(&vw.done);
  if (vw.err_code != 0) {
    fprintf(stderr, "get_value: %s\n", vw.err[0] ? vw.err : "unknown");
    goto cleanup_client;
  }
  printf("Client fetched: %.*s\n", (int)vw.len, vw.data);
  if (vw.len != value.len || memcmp(vw.data, ValueData, vw.len) != 0) {
    fprintf(stderr, "Error: fetched value does not match\n");
    goto cleanup_client;
  }

  // ── Provider round-trip: server advertises a CID, client discovers it ─────
  CidWaiter cw;
  memset(&cw, 0, sizeof(cw));
  const char *cidData = "cbind-kad";
  CreateCidRequest cidReq = {CID_VERSION_V1,
                             nimffi_str("raw"),
                             nimffi_str("sha2-256"),
                             {(uint8_t *)cidData, strlen(cidData)}};
  // create_cid is context-independent ({.ffiStatic.}), so it takes no ctx.
  libp2p_static_create_cid(&cidReq, on_cid, &cw);
  wait_done(&cw.done);
  if (cw.err_code != 0) {
    fprintf(stderr, "create_cid: %s\n", cw.err[0] ? cw.err : "unknown");
    goto cleanup_client;
  }
  printf("CID: %s\n", cw.cid);

  if (!AWAIT_BOOL(bw,
                  libp2p_ctx_kad_start_providing(server, nimffi_str(cw.cid),
                                                 on_bool, &bw),
                  "start_providing"))
    goto cleanup_client;
  printf("Server is providing %s\n", cw.cid);

  ProvidersWaiter pw;
  memset(&pw, 0, sizeof(pw));
  libp2p_ctx_kad_get_providers(client, nimffi_str(cw.cid), on_providers, &pw);
  wait_done(&pw.done);
  if (pw.err_code != 0) {
    fprintf(stderr, "get_providers: %s\n", pw.err[0] ? pw.err : "unknown");
    goto cleanup_client;
  }
  printf("Client found %zu provider(s)\n", pw.n);

  bool serverIsProvider = false;
  for (size_t i = 0; i < pw.n; i++) {
    printf("  provider: %s\n", pw.peerIds[i]);
    if (strcmp(pw.peerIds[i], serverInfo.peerId) == 0)
      serverIsProvider = true;
  }
  if (serverIsProvider)
    status = 0;
  else
    fprintf(stderr, "Error: server not found among providers\n");

cleanup_client:
  AWAIT_BOOL(bw, libp2p_ctx_stop(client, on_bool, &bw), "stop client");
  libp2p_ctx_destroy(client);
cleanup_server:
  AWAIT_BOOL(bw, libp2p_ctx_stop(server, on_bool, &bw), "stop server");
  libp2p_ctx_destroy(server);
  return status;
}
