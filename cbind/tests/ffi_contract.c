// A parse error and a lifecycle error reach the C host with the exact message.
#include "../examples/common.h"

#include <inttypes.h>

typedef struct {
  const char *name;
  Libp2pConfig cfg;
  char want[256];
} BadConfig;

static bool rejectsConfig(const BadConfig *c) {
  CreateWaiter w;
  memset(&w, 0, sizeof(w));
  libp2p_ctx_create(&c->cfg, on_created, &w);
  wait_done(&w.done);
  if (w.ctx)
    libp2p_ctx_destroy(w.ctx);
  if (w.err_code == 0) {
    fprintf(stderr, "%s: create succeeded\n", c->name);
    return false;
  }
  if (strcmp(w.err, c->want) != 0) {
    fprintf(stderr, "%s: want '%s', got '%s'\n", c->name, c->want, w.err);
    return false;
  }
  printf("%s rejected: %s\n", c->name, w.err);
  return true;
}

static bool rejectsBadConfigs(void) {
  BadConfig cases[2];
  memset(cases, 0, sizeof(cases));

  cases[0].name = "service discovery setting without mount";
  cases[0].cfg.transports = TRANSPORT_TCP;
  cases[0].cfg.serviceDiscovery.disableXprPublishing = true;
  snprintf(cases[0].want, sizeof(cases[0].want),
           "service discovery settings require serviceDiscovery.mount");

  cases[1].name = "gossipsub maxMessageSize above the limit";
  cases[1].cfg.transports = TRANSPORT_TCP;
  cases[1].cfg.gossipsub.mount = true;
  cases[1].cfg.gossipsub.maxMessageSize = MAX_GOSSIPSUB_MESSAGE_SIZE + 1;
  snprintf(cases[1].want, sizeof(cases[1].want),
           "maxMessageSize exceeds the limit of %" PRId64 " bytes (%" PRId64
           ")",
           MAX_GOSSIPSUB_MESSAGE_SIZE, MAX_GOSSIPSUB_MESSAGE_SIZE + 1);

  bool ok = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    ok = rejectsConfig(&cases[i]) && ok;
  return ok;
}

// Discovery needs a listening switch (issue #3003).
static bool rejectsDiscoBeforeStart(void) {
  NimFfiStr addrSlot = nimffi_str("/ip4/127.0.0.1/tcp/0");
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.serviceDiscovery.mount = true;
  cfg.addrs.data = &addrSlot;
  cfg.addrs.len = 1;
  cfg.transports = TRANSPORT_TCP;
  LibP2PCtx *ctx = await_create(&cfg, "disco node");
  if (!ctx)
    return false;

  BoolWaiter bw;
  memset(&bw, 0, sizeof(bw));
  libp2p_ctx_service_disco_start(ctx, on_bool, &bw);
  wait_done(&bw.done);
  libp2p_ctx_destroy(ctx);

  const char *want = "switch not started; call libp2p_ctx_start first";
  if (bw.err_code == 0 || strcmp(bw.err, want) != 0) {
    fprintf(stderr,
            "service_disco_start before ctx_start: want '%s', got %d '%s'\n",
            want, bw.err_code, bw.err);
    return false;
  }
  printf("service_disco_start before ctx_start rejected: %s\n", bw.err);
  return true;
}

int main(void) {
  bool ok = rejectsBadConfigs();
  ok = rejectsDiscoBeforeStart() && ok;
  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
