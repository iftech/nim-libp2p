// Service discovery: a provider advertises a service id in its extended peer
// record, and a seeker that bootstraps off the provider looks the service up
// over the DHT. The generated bindings are asynchronous, so every call is
// wrapped with the blocking helpers in common.h.
//
// Ordering matters here. The switch lifecycle already starts and stops
// discovery, so `libp2p_ctx_start` comes first and every
// `libp2p_ctx_service_disco_*` call before it fails with an explicit error
// rather than half-starting an undialable node.
#include "common.h"

static const char *ServiceId = "/cbind/disco/demo-service";
static const char *ServiceData = "demo-payload";
// Replaces the 900 s core default.
static const int64_t AdvertExpiryMs = 120000;

// A lookup answers with up to Default_F_lookup (30) records.
#define MAX_RECORDS 32
typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  char peerIds[MAX_RECORDS][128];
  bool advertises[MAX_RECORDS];
  char serviceData[MAX_RECORDS][128];
  size_t n;
} RecordsWaiter;

static void copyServiceData(const ExtendedPeerRecordEntry *r, char *dst,
                            size_t cap, bool *found) {
  for (size_t i = 0; i < r->services.len; i++) {
    const ServiceInfoEntry *s = &r->services.data[i];
    if (!s->id.data || strcmp(s->id.data, ServiceId) != 0)
      continue;
    *found = true;
    if (s->data.data)
      snprintf(dst, cap, "%.*s", (int)s->data.len, (const char *)s->data.data);
    return;
  }
}

static void on_records(int ec, const ExtendedRecordsResponse *reply,
                       const char *em, void *ud) {
  RecordsWaiter *w = (RecordsWaiter *)ud;
  w->err_code = ec;
  if (reply) {
    w->n = reply->records.len < MAX_RECORDS ? reply->records.len : MAX_RECORDS;
    for (size_t i = 0; i < w->n; i++) {
      const ExtendedPeerRecordEntry *r = &reply->records.data[i];
      if (r->peerId.data)
        snprintf(w->peerIds[i], sizeof(w->peerIds[i]), "%s", r->peerId.data);
      copyServiceData(r, w->serviceData[i], sizeof(w->serviceData[i]),
                      &w->advertises[i]);
    }
  }
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

static LibP2PCtx *discoNode(const char *listenAddr, const char *label,
                            const PeerInfoWaiter *boot) {
  NimFfiStr addrSlot = nimffi_str(listenAddr);
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.serviceDiscovery.mount = true;
  cfg.serviceDiscovery.advertExpiryMs = AdvertExpiryMs;
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
  return await_create(&cfg, label);
}

// Registration is a background task, so the lookup retries.
#define LOOKUP_ATTEMPTS 30
static bool lookupProvider(LibP2PCtx *seeker, const char *providerId) {
  LookupRequest req = {nimffi_str(ServiceId), {NULL, 0}};
  for (int attempt = 0; attempt < LOOKUP_ATTEMPTS; attempt++) {
    RecordsWaiter rw;
    memset(&rw, 0, sizeof(rw));
    libp2p_ctx_service_disco_lookup(seeker, &req, on_records, &rw);
    wait_done(&rw.done);
    if (rw.err_code != 0) {
      fprintf(stderr, "lookup: %s\n", rw.err[0] ? rw.err : "unknown");
      return false;
    }
    for (size_t i = 0; i < rw.n; i++) {
      if (!rw.advertises[i] || strcmp(rw.peerIds[i], providerId) != 0)
        continue;
      if (strcmp(rw.serviceData[i], ServiceData) != 0) {
        fprintf(stderr, "Error: service data did not round-trip\n");
        return false;
      }
      printf("Seeker found %s advertising '%s' with '%s'\n", providerId,
             ServiceId, ServiceData);
      return true;
    }
    sleep_ms(500);
  }
  fprintf(stderr, "Error: provider never showed up in a lookup\n");
  return false;
}

// Discovery cannot be driven before the switch listens (issue #3003).
static bool rejectsDiscoBeforeStart(LibP2PCtx *ctx) {
  BoolWaiter bw;
  memset(&bw, 0, sizeof(bw));
  libp2p_ctx_service_disco_start(ctx, on_bool, &bw);
  wait_done(&bw.done);
  if (bw.err_code == 0) {
    fprintf(stderr, "Error: service_disco_start succeeded before ctx_start\n");
    return false;
  }
  // A bare err_code check also passes on an unmounted protocol.
  if (strstr(bw.err, "switch not started") == NULL) {
    fprintf(stderr, "Error: expected the not-started guard, got: %s\n", bw.err);
    return false;
  }
  printf("service_disco_start before ctx_start rejected: %s\n", bw.err);
  return true;
}

int main(void) {
  int status = 1;
  BoolWaiter bw;
  PeerInfoWaiter providerInfo;

  LibP2PCtx *provider = discoNode("/ip4/127.0.0.1/tcp/5041", "provider", NULL);
  if (!provider)
    return 1;
  if (!rejectsDiscoBeforeStart(provider))
    goto cleanup_provider;
  if (!AWAIT_BOOL(bw, libp2p_ctx_start(provider, on_bool, &bw),
                  "start provider"))
    goto cleanup_provider;
  if (!await_peerinfo(provider, &providerInfo, "provider peerinfo"))
    goto cleanup_provider;
  printf("Provider: %s\n", providerInfo.peerId);

  LibP2PCtx *seeker =
      discoNode("/ip4/127.0.0.1/tcp/5042", "seeker", &providerInfo);
  if (!seeker)
    goto cleanup_provider;
  if (!AWAIT_BOOL(bw, libp2p_ctx_start(seeker, on_bool, &bw), "start seeker") ||
      !await_connect(seeker, &providerInfo))
    goto cleanup_seeker;

  StartAdvertisingRequest adReq = {
      nimffi_str(ServiceId),
      {(uint8_t *)ServiceData, strlen(ServiceData)},
      {NULL, 0}};
  if (!AWAIT_BOOL(bw,
                  libp2p_ctx_service_disco_start_advertising(provider, &adReq,
                                                             on_bool, &bw),
                  "start_advertising"))
    goto cleanup_seeker;
  printf("Provider advertises '%s'\n", ServiceId);

  if (lookupProvider(seeker, providerInfo.peerId))
    status = 0;

cleanup_seeker:
  AWAIT_BOOL(bw, libp2p_ctx_stop(seeker, on_bool, &bw), "stop seeker");
  libp2p_ctx_destroy(seeker);
cleanup_provider:
  AWAIT_BOOL(bw, libp2p_ctx_stop(provider, on_bool, &bw), "stop provider");
  libp2p_ctx_destroy(provider);
  return status;
}
