// Metrics: a running node dumps the process-wide Prometheus registry as JSON
// via libp2p_static_collect_metrics. The registry is global, so one started
// node is enough to populate it. Calls are made blocking with the helpers in
// common.h.
#include "common.h"

// collect_metrics replies with a JSON string (Result[string]).
typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  char json[1 << 16];
  size_t len;
} MetricsWaiter;

static void on_metrics(int ec, const NimFfiStr *reply, const char *em,
                       void *ud) {
  MetricsWaiter *w = (MetricsWaiter *)ud;
  w->err_code = ec;
  if (reply && reply->data) {
    w->len =
        reply->len < sizeof(w->json) - 1 ? reply->len : sizeof(w->json) - 1;
    memcpy(w->json, reply->data, w->len);
    w->json[w->len] = '\0';
  }
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

int main(void) {
  NimFfiStr addr = nimffi_str("/ip4/127.0.0.1/tcp/5041");
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.addrs.data = &addr;
  cfg.addrs.len = 1;
  cfg.muxer = MUXER_TYPE_MPLEX;
  cfg.transports = TRANSPORT_TCP;

  LibP2PCtx *node = await_create(&cfg, "node");
  if (!node)
    return 1;

  int status = 1;
  BoolWaiter bw;
  if (!AWAIT_BOOL(bw, libp2p_ctx_start(node, on_bool, &bw), "start"))
    goto cleanup;

  MetricsWaiter mw;
  memset(&mw, 0, sizeof(mw));
  libp2p_static_collect_metrics(on_metrics, &mw);
  wait_done(&mw.done);
  if (mw.err_code != 0) {
    fprintf(stderr, "collect_metrics: %s\n", mw.err[0] ? mw.err : "unknown");
    goto cleanup;
  }

  // A JSON array of {name,type,help,labels,value,timestamp} objects; print a
  // prefix rather than the whole document.
  printf("Collected %zu bytes of metrics\n", mw.len);
  printf("%.400s%s\n", mw.json, mw.len > 400 ? " ..." : "");

  if (mw.json[0] == '[' && strstr(mw.json, "\"name\""))
    status = 0;
  else
    fprintf(stderr, "Error: metrics payload was empty or malformed\n");

cleanup:
  AWAIT_BOOL(bw, libp2p_ctx_stop(node, on_bool, &bw), "stop");
  libp2p_ctx_destroy(node);
  return status;
}
