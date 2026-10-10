/* Router port mapping (spec 5.5): PCP (RFC 6887), NAT-PMP (RFC 6886) and
   UPnP-IGD, all non-blocking, all on by default. A successful mapping turns
   this host into an "open" peer: the mapped public address is advertised as
   a candidate that accepts traffic from anyone, which is what lets peers
   behind symmetric NATs reach us directly.

   The UPnP part contains the library's only HTTP: a minimal client that
   only ever talks to the local router (spec 1 non-goals). */
#include <stdio.h>
#include <stdlib.h>

#include "core.h"
#include "crypto.h"

#define PMP_PORT 5351
#define PMP_TRIES 3
#define LEASE_S 7200
#define UPNP_LEASE_S 7200
#define HTTP_TIMEOUT_US 3000000
#define SSDP_WINDOW_US 3000000
#define HTTP_MAX 65536

enum { PMP_IDLE = 0, PMP_PCP, PMP_NATPMP, PMP_MAPPED, PMP_FAILED };
enum { U_IDLE = 0, U_DISCOVER, U_DESC, U_EXTIP, U_ADD, U_MAPPED, U_FAILED };
enum { H_NONE = 0, H_CONNECTING, H_SENDING, H_RECEIVING };

struct pc_portmap {
    uint8_t started;
    uint8_t has_gw;
    pierce_addr gw;                 /* router, port PMP_PORT */
    pierce_addr lan_ip;             /* our address on the router's LAN */
    uint16_t int_port;              /* our primary IPv4 port */

    /* PCP / NAT-PMP */
    uint8_t pmp_state;
    uint8_t pmp_proto;              /* PMP_PCP or PMP_NATPMP once mapped */
    uint8_t nonce[12];
    uint32_t pmp_tries;
    uint64_t pmp_next_us;
    pierce_addr pmp_ext;            /* NAT-PMP learns IP and port separately */
    uint8_t pmp_have_ip, pmp_have_port;
    uint32_t pmp_life;
    uint64_t pmp_refresh_us;

    /* UPnP */
    uint8_t u_state;
    uint32_t u_tries;
    uint64_t u_next_us, u_deadline_us, u_refresh_us;
    pierce_addr ssdp;               /* 239.255.255.250:1900 */
    uint8_t has_ssdp;
    pierce_addr u_http;             /* router's HTTP endpoint */
    char u_desc_path[256], u_ctrl_path[256], u_svc[128];
    pierce_addr u_ext;
    uint16_t u_ext_port;
    uint32_t u_lease;
    uint8_t u_conflicts;
    uint8_t h_state;
    pal_sock h_sock;
    uint8_t *h_req;
    uint32_t h_req_len, h_req_off;
    uint8_t *h_resp;
    uint32_t h_resp_len;

    /* result */
    uint8_t advertised;             /* 1 = PCP/NAT-PMP, 2 = UPnP */
    pierce_addr adv;
    uint8_t refused_logged;
};

/* Test hooks: tests have no real router, so they point us at fakes. */
void pierce__test_set_gateway(pierce_ctx *ctx, const pierce_addr *gw);
void pierce__test_set_ssdp(pierce_ctx *ctx, const pierce_addr *target);

static int ensure(pierce_ctx *ctx)
{
    if (ctx->pm) return 1;
    ctx->pm = (pc_portmap *)pc_alloc(&ctx->alloc, sizeof(pc_portmap));
    if (!ctx->pm) return 0;
    ctx->pm->h_sock = PAL_INVALID_SOCK;
    return 1;
}

void pierce__test_set_gateway(pierce_ctx *ctx, const pierce_addr *gw)
{
    if (!ensure(ctx)) return;
    ctx->pm->gw = *gw;
    ctx->pm->gw.port = PMP_PORT;
    ctx->pm->has_gw = 1;
}

void pierce__test_set_ssdp(pierce_ctx *ctx, const pierce_addr *target)
{
    if (!ensure(ctx)) return;
    ctx->pm->ssdp = *target;
    ctx->pm->has_ssdp = 1;
}

static int disabled(pierce_ctx *ctx)
{
    return (ctx->flags & (PIERCE_CFG_NO_PORT_MAPPING | PIERCE_CFG_RELAY_ONLY | PIERCE_CFG_NO_IPV4)) != 0;
}

/* Usable as a public candidate: not private, CGNAT, loopback or zero. */
static int public_v4(const pierce_addr *a)
{
    static const uint8_t zero[4];
    return a->family == PIERCE_AF_INET && !pc_addr_is_private(a) && memcmp(a->addr, zero, 4) != 0 &&
           a->addr[0] != 0 && a->addr[0] < 224;
}

static void advertise(pierce_ctx *ctx, uint8_t source, const pierce_addr *ext)
{
    pc_portmap *pm = ctx->pm;
    char a[64];
    pierce_addr_format(ext, a, sizeof(a));
    if (!public_v4(ext)) {
        /* The router's "external" address is itself private: there is
           another NAT upstream (double NAT or carrier-grade NAT). */
        if (!pm->refused_logged)
            pc_log(ctx, PIERCE_LOG_INFO, "port mapping: router reports %s, another NAT is upstream; not using it", a);
        pm->refused_logged = 1;
        return;
    }
    if (pm->advertised && pm->advertised != source) return;   /* first technique wins */
    if (pm->advertised && pc_addr_eq(&pm->adv, ext)) return;
    pm->advertised = source;
    pm->adv = *ext;
    pc_log(ctx, PIERCE_LOG_INFO, "port mapping: %s via %s", a, source == 1 ? "PCP/NAT-PMP" : "UPnP");
    pc_gather_cands_rebuild(ctx);
}

static void withdraw(pierce_ctx *ctx, uint8_t source)
{
    if (ctx->pm->advertised != source) return;
    ctx->pm->advertised = 0;
    pc_gather_cands_rebuild(ctx);
}

int pc_portmap_advertised(pierce_ctx *ctx, pierce_addr *out)
{
    if (!ctx->pm || !ctx->pm->advertised) return 0;
    *out = ctx->pm->adv;
    return 1;
}

void pc_portmap_reject(pierce_ctx *ctx)
{
    /* STUN saw a different public address: the mapping is on an inner
       router of a double NAT. Stop advertising it. */
    if (!ctx->pm || !ctx->pm->advertised) return;
    pc_log(ctx, PIERCE_LOG_INFO, "port mapping: STUN disagrees with the router's address (double NAT); not using it");
    ctx->pm->advertised = 0;
    ctx->pm->refused_logged = 1;
}

/* ===================================================================== */
/* PCP and NAT-PMP                                                       */
/* ===================================================================== */

static void v4mapped(uint8_t out[16], const pierce_addr *a)
{
    memset(out, 0, 10);
    out[10] = out[11] = 0xff;
    if (a) memcpy(out + 12, a->addr, 4);
    else memset(out + 12, 0, 4);
}

static void pcp_send(pierce_ctx *ctx, uint32_t lifetime)
{
    pc_portmap *pm = ctx->pm;
    uint8_t p[60];
    memset(p, 0, sizeof(p));
    p[0] = 2;                        /* version */
    p[1] = 1;                        /* MAP request */
    pc_put32(p + 4, lifetime);
    v4mapped(p + 8, &pm->lan_ip);
    memcpy(p + 24, pm->nonce, 12);
    p[36] = 17;                      /* UDP */
    pc_put16(p + 40, pm->int_port);
    pc_put16(p + 42, pm->int_port);  /* suggest the same external port */
    v4mapped(p + 44, NULL);
    pc_send_direct(ctx, &pm->gw, p, sizeof(p));
}

static void natpmp_send(pierce_ctx *ctx, uint32_t lifetime)
{
    pc_portmap *pm = ctx->pm;
    uint8_t ext_req[2] = {0, 0};
    uint8_t map[12];
    map[0] = 0;
    map[1] = 1;                      /* map UDP */
    map[2] = map[3] = 0;
    pc_put16(map + 4, pm->int_port);
    pc_put16(map + 6, pm->int_port);
    pc_put32(map + 8, lifetime);
    if (lifetime) pc_send_direct(ctx, &pm->gw, ext_req, sizeof(ext_req));
    pc_send_direct(ctx, &pm->gw, map, sizeof(map));
}

static void pmp_mapped(pierce_ctx *ctx, uint32_t life)
{
    pc_portmap *pm = ctx->pm;
    uint64_t now = pc_now(ctx);
    pm->pmp_proto = pm->pmp_state;
    pm->pmp_state = PMP_MAPPED;
    pm->pmp_life = life;
    pm->pmp_tries = 0;
    uint64_t half = (uint64_t)PC_MAX(life, 120u) * 500000;   /* refresh at half the lease */
    pm->pmp_refresh_us = now + half;
    advertise(ctx, 1, &pm->pmp_ext);
}

static void pmp_input(pierce_ctx *ctx, const uint8_t *p, size_t len)
{
    pc_portmap *pm = ctx->pm;
    if (pm->pmp_state == PMP_IDLE || pm->pmp_state == PMP_FAILED) return;
    if (len >= 4 && p[0] == 2 && p[1] == 0x81) {                 /* PCP MAP response */
        if (len < 60 || memcmp(p + 24, pm->nonce, 12) != 0) return;
        if (p[3] != 0) {
            pc_log(ctx, PIERCE_LOG_DEBUG, "PCP: mapping refused (result %u)", p[3]);
            pm->pmp_state = PMP_NATPMP;    /* some routers do NAT-PMP better than PCP */
            pm->pmp_tries = 0;
            pm->pmp_next_us = pc_now(ctx);
            return;
        }
        memset(&pm->pmp_ext, 0, sizeof(pm->pmp_ext));
        pm->pmp_ext.family = PIERCE_AF_INET;
        memcpy(pm->pmp_ext.addr, p + 56, 4);
        pm->pmp_ext.port = pc_get16(p + 42);
        pmp_mapped(ctx, pc_get32(p + 4));
        return;
    }
    if (len >= 4 && p[0] == 0) {                                 /* NAT-PMP (or PCP refusal from one) */
        uint16_t result = pc_get16(p + 2);
        if (pm->pmp_state == PMP_PCP) {
            if (result == 1) {           /* unsupported version: speaks NAT-PMP only */
                pm->pmp_state = PMP_NATPMP;
                pm->pmp_tries = 0;
                pm->pmp_next_us = pc_now(ctx);
            }
            return;
        }
        if (result != 0) {
            pc_log(ctx, PIERCE_LOG_DEBUG, "NAT-PMP: request refused (result %u)", result);
            pm->pmp_state = PMP_FAILED;
            return;
        }
        if (p[1] == 128 && len >= 12) {
            pm->pmp_ext.family = PIERCE_AF_INET;
            memcpy(pm->pmp_ext.addr, p + 8, 4);
            pm->pmp_have_ip = 1;
        } else if (p[1] == 129 && len >= 16) {
            pm->pmp_ext.family = PIERCE_AF_INET;
            pm->pmp_ext.port = pc_get16(p + 10);
            pm->pmp_life = pc_get32(p + 12);
            pm->pmp_have_port = 1;
        }
        if (pm->pmp_have_ip && pm->pmp_have_port && pm->pmp_state != PMP_MAPPED) pmp_mapped(ctx, pm->pmp_life);
        else if (pm->pmp_have_ip && pm->pmp_have_port) advertise(ctx, 1, &pm->pmp_ext);
    }
}

static void pmp_timers(pierce_ctx *ctx, uint64_t now)
{
    pc_portmap *pm = ctx->pm;
    switch (pm->pmp_state) {
    case PMP_PCP:
    case PMP_NATPMP:
        if (now < pm->pmp_next_us) return;
        if (pm->pmp_tries >= PMP_TRIES) {
            if (pm->pmp_state == PMP_PCP) {
                pm->pmp_state = PMP_NATPMP;
                pm->pmp_tries = 0;
            } else {
                pm->pmp_state = PMP_FAILED;
                pc_log(ctx, PIERCE_LOG_DEBUG, "PCP/NAT-PMP: no answer from the router");
                withdraw(ctx, 1);   /* a refresh that went unanswered */
                return;
            }
        }
        if (pm->pmp_state == PMP_PCP) pcp_send(ctx, LEASE_S);
        else natpmp_send(ctx, LEASE_S);
        pm->pmp_next_us = now + (250000ull << pm->pmp_tries);
        pm->pmp_tries++;
        break;
    case PMP_MAPPED:
        if (now >= pm->pmp_refresh_us) {
            /* Refresh by re-requesting with the protocol that worked. */
            pm->pmp_state = pm->pmp_proto;
            pm->pmp_have_ip = pm->pmp_have_port = 0;
            pm->pmp_tries = 0;
            pm->pmp_next_us = now;
        }
        break;
    default:
        break;
    }
}

static uint64_t pmp_next(const pc_portmap *pm)
{
    if (pm->pmp_state == PMP_PCP || pm->pmp_state == PMP_NATPMP) return pm->pmp_next_us;
    if (pm->pmp_state == PMP_MAPPED) return pm->pmp_refresh_us;
    return 0;
}

/* ===================================================================== */
/* Tiny HTTP and XML helpers (UPnP only)                                 */
/* ===================================================================== */

static int lower(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static const char *find_ci(const char *hay, size_t n, const char *needle)
{
    size_t k = strlen(needle);
    for (size_t i = 0; i + k <= n; i++) {
        size_t j = 0;
        while (j < k && lower((unsigned char)hay[i + j]) == lower((unsigned char)needle[j])) j++;
        if (j == k) return hay + i;
    }
    return NULL;
}

/* Text of the first element named `tag` at or after `from`, ignoring any
   namespace prefix. Returns a pointer just past the element, or NULL. */
static const char *xml_text(const char *body, size_t n, const char *from, const char *tag, char *out, size_t cap)
{
    const char *end = body + n;
    size_t tl = strlen(tag);
    for (const char *p = from ? from : body; p < end; p++) {
        if (*p != '<' || p + 1 >= end || p[1] == '/') continue;
        const char *name = p + 1, *ne = name;
        while (ne < end && *ne != '>' && *ne != ' ' && *ne != '/') ne++;
        if (ne >= end || *ne == '/') continue;
        const char *colon = memchr(name, ':', (size_t)(ne - name));
        if (colon) name = colon + 1;
        if ((size_t)(ne - name) != tl || memcmp(name, tag, tl) != 0) continue;
        const char *gt = memchr(ne, '>', (size_t)(end - ne));
        if (!gt) return NULL;
        const char *val = gt + 1, *lt = memchr(val, '<', (size_t)(end - val));
        if (!lt) return NULL;
        size_t vl = (size_t)(lt - val);
        while (vl && (val[0] == ' ' || val[0] == '\n' || val[0] == '\r' || val[0] == '\t')) { val++; vl--; }
        while (vl && (val[vl - 1] == ' ' || val[vl - 1] == '\n' || val[vl - 1] == '\r' || val[vl - 1] == '\t')) vl--;
        if (vl >= cap) vl = cap - 1;
        memcpy(out, val, vl);
        out[vl] = 0;
        return lt;
    }
    return NULL;
}

/* "http://1.2.3.4:5000/path" -> address and path. Hostnames are not
   resolved: routers advertise numeric addresses. */
static int parse_http_url(const char *url, pierce_addr *addr, char *path, size_t pcap)
{
    char hostport[80];
    if (strncmp(url, "http://", 7) != 0) return -1;
    const char *h = url + 7, *slash = strchr(h, '/');
    size_t hl = slash ? (size_t)(slash - h) : strlen(h);
    if (hl == 0 || hl >= sizeof(hostport) - 4) return -1;
    memcpy(hostport, h, hl);
    hostport[hl] = 0;
    if (!strchr(hostport, ':')) strcat(hostport, ":80");
    if (pierce_addr_parse(hostport, addr) != PIERCE_OK) return -1;
    snprintf(path, pcap, "%s", slash ? slash : "/");
    return 0;
}

static void http_close(pc_portmap *pm, pierce_ctx *ctx)
{
    if (pm->h_sock != PAL_INVALID_SOCK) pal_sock_close(pm->h_sock);
    pm->h_sock = PAL_INVALID_SOCK;
    pm->h_state = H_NONE;
    pc_free(&ctx->alloc, pm->h_req);
    pm->h_req = NULL;
    pm->h_req_len = pm->h_req_off = 0;
}

static int http_begin(pierce_ctx *ctx, const char *req, size_t len)
{
    pc_portmap *pm = ctx->pm;
    http_close(pm, ctx);
    pm->h_req = (uint8_t *)pc_alloc(&ctx->alloc, len);
    if (!pm->h_req) return -1;
    if (!pm->h_resp) pm->h_resp = (uint8_t *)pc_alloc(&ctx->alloc, HTTP_MAX + 1);
    if (!pm->h_resp) return -1;
    memcpy(pm->h_req, req, len);
    pm->h_req_len = (uint32_t)len;
    pm->h_resp_len = 0;
    if (pal_tcp_connect(&pm->u_http, &pm->h_sock) != PIERCE_OK) return -1;
    pm->h_state = H_CONNECTING;
    pm->u_deadline_us = pc_now(ctx) + HTTP_TIMEOUT_US;
    return 0;
}

static int build_get(const pc_portmap *pm, char *out, size_t cap, const char *path)
{
    char host[64];
    pierce_addr_format(&pm->u_http, host, sizeof(host));
    return snprintf(out, cap, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);
}

static int build_soap(const pc_portmap *pm, char *out, size_t cap, const char *action, const char *args)
{
    char host[64], body[2048];
    pierce_addr_format(&pm->u_http, host, sizeof(host));
    int bl = snprintf(body, sizeof(body),
                      "<?xml version=\"1.0\"?>\r\n"
                      "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                      "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>"
                      "<u:%s xmlns:u=\"%s\">%s</u:%s></s:Body></s:Envelope>\r\n",
                      action, pm->u_svc, args, action);
    return snprintf(out, cap,
                    "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n"
                    "SOAPAction: \"%s#%s\"\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
                    pm->u_ctrl_path, host, pm->u_svc, action, bl, body);
}

static int build_add(const pc_portmap *pm, char *out, size_t cap)
{
    char args[700], ip[64];
    snprintf(ip, sizeof(ip), "%u.%u.%u.%u", pm->lan_ip.addr[0], pm->lan_ip.addr[1], pm->lan_ip.addr[2],
             pm->lan_ip.addr[3]);
    snprintf(args, sizeof(args),
             "<NewRemoteHost></NewRemoteHost><NewExternalPort>%u</NewExternalPort>"
             "<NewProtocol>UDP</NewProtocol><NewInternalPort>%u</NewInternalPort>"
             "<NewInternalClient>%s</NewInternalClient><NewEnabled>1</NewEnabled>"
             "<NewPortMappingDescription>pierce</NewPortMappingDescription>"
             "<NewLeaseDuration>%u</NewLeaseDuration>",
             pm->u_ext_port, pm->int_port, ip, pm->u_lease);
    return build_soap(pm, out, cap, "AddPortMapping", args);
}

static int build_delete(const pc_portmap *pm, char *out, size_t cap)
{
    char args[256];
    snprintf(args, sizeof(args),
             "<NewRemoteHost></NewRemoteHost><NewExternalPort>%u</NewExternalPort><NewProtocol>UDP</NewProtocol>",
             pm->u_ext_port);
    return build_soap(pm, out, cap, "DeletePortMapping", args);
}

/* Splits a complete response: status code, and body (dechunked in place). */
static int http_parse(uint8_t *buf, uint32_t len, char **body, size_t *blen)
{
    buf[len] = 0;
    char *s = (char *)buf;
    if (len < 12 || strncmp(s, "HTTP/1.", 7) != 0) return -1;
    int status = atoi(s + 9);
    char *hdr_end = strstr(s, "\r\n\r\n");
    if (!hdr_end) return -1;
    char *b = hdr_end + 4;
    size_t n = len - (uint32_t)(b - s);
    if (find_ci(s, (size_t)(hdr_end - s), "transfer-encoding: chunked")) {
        char *in = b, *out = b, *end = b + n;
        while (in < end) {
            unsigned long csz = strtoul(in, NULL, 16);
            char *crlf = strstr(in, "\r\n");
            if (!crlf || csz == 0) break;
            in = crlf + 2;
            if ((size_t)(end - in) < csz) csz = (unsigned long)(end - in);
            memmove(out, in, csz);
            out += csz;
            in += csz + 2;
        }
        n = (size_t)(out - b);
        b[n] = 0;
    }
    *body = b;
    *blen = n;
    return status;
}

/* ===================================================================== */
/* UPnP state machine                                                    */
/* ===================================================================== */

static void u_fail(pierce_ctx *ctx, const char *why)
{
    pc_portmap *pm = ctx->pm;
    http_close(pm, ctx);
    if (pm->u_state != U_FAILED) pc_log(ctx, PIERCE_LOG_DEBUG, "UPnP: %s", why);
    pm->u_state = U_FAILED;
    withdraw(ctx, 2);
}

static void u_request(pierce_ctx *ctx, int kind)
{
    pc_portmap *pm = ctx->pm;
    char req[4096];
    int n;
    if (kind == U_DESC) n = build_get(pm, req, sizeof(req), pm->u_desc_path);
    else if (kind == U_EXTIP) n = build_soap(pm, req, sizeof(req), "GetExternalIPAddress", "");
    else n = build_add(pm, req, sizeof(req));
    if (n <= 0 || (size_t)n >= sizeof(req) || http_begin(ctx, req, (size_t)n) < 0) {
        u_fail(ctx, "cannot reach the router's HTTP endpoint");
        return;
    }
    pm->u_state = (uint8_t)kind;
}

static void u_response(pierce_ctx *ctx, int status, const char *body, size_t blen)
{
    pc_portmap *pm = ctx->pm;
    char val[512];
    switch (pm->u_state) {
    case U_DESC: {
        if (status != 200) {
            u_fail(ctx, "device description request failed");
            return;
        }
        /* Prefer WANIPConnection; WANPPPConnection for PPPoE routers. */
        static const char *kinds[] = {"WANIPConnection:", "WANPPPConnection:"};
        int found = 0;
        for (int k = 0; k < 2 && !found; k++) {
            const char *at = NULL;
            while ((at = xml_text(body, blen, at, "serviceType", val, sizeof(val)))) {
                if (!strstr(val, kinds[k])) continue;
                char ctrl[256];
                if (!xml_text(body, blen, at, "controlURL", ctrl, sizeof(ctrl))) break;
                if (strlen(val) >= sizeof(pm->u_svc)) continue;
                memcpy(pm->u_svc, val, strlen(val) + 1);
                char base[256] = "";
                xml_text(body, blen, NULL, "URLBase", base, sizeof(base));
                pierce_addr a;
                char path[256];
                if (!strncmp(ctrl, "http://", 7)) {
                    if (parse_http_url(ctrl, &a, path, sizeof(path)) < 0) break;
                    pm->u_http = a;
                    snprintf(pm->u_ctrl_path, sizeof(pm->u_ctrl_path), "%s", path);
                } else {
                    if (base[0] && parse_http_url(base, &a, path, sizeof(path)) == 0) pm->u_http = a;
                    size_t cl = strlen(ctrl), pre = ctrl[0] == '/' ? 0 : 1;
                    if (cl + pre >= sizeof(pm->u_ctrl_path)) break;
                    pm->u_ctrl_path[0] = '/';
                    memcpy(pm->u_ctrl_path + pre, ctrl, cl + 1);
                }
                found = 1;
                break;
            }
        }
        if (!found) {
            u_fail(ctx, "router has no WAN connection service");
            return;
        }
        u_request(ctx, U_EXTIP);
        return;
    }
    case U_EXTIP:
        if (status != 200 || !xml_text(body, blen, NULL, "NewExternalIPAddress", val, sizeof(val))) {
            u_fail(ctx, "GetExternalIPAddress failed");
            return;
        }
        {
            char tmp[64];
            size_t vl = strlen(val);
            if (vl > 40) vl = 40;            /* longer than any IPv4 literal: parse fails below */
            memcpy(tmp, val, vl);
            memcpy(tmp + vl, ":0", 3);
            if (pierce_addr_parse(tmp, &pm->u_ext) != PIERCE_OK) {
                u_fail(ctx, "router returned a malformed external address");
                return;
            }
        }
        if (!public_v4(&pm->u_ext)) {
            advertise(ctx, 2, &pm->u_ext);   /* logs the double-NAT diagnosis */
            u_fail(ctx, "router's external address is not public");
            return;
        }
        pm->u_ext_port = pm->int_port;
        pm->u_lease = UPNP_LEASE_S;
        pm->u_conflicts = 0;
        u_request(ctx, U_ADD);
        return;
    case U_ADD:
        if (status == 200) {
            uint64_t now = pc_now(ctx);
            pm->u_state = U_MAPPED;
            pm->u_refresh_us = pm->u_lease ? now + (uint64_t)pm->u_lease * 500000 : 0;
            pierce_addr ext = pm->u_ext;
            ext.port = pm->u_ext_port;
            advertise(ctx, 2, &ext);
            return;
        }
        {
            int code = xml_text(body, blen, NULL, "errorCode", val, sizeof(val)) ? atoi(val) : 0;
            if (code == 725 && pm->u_lease) {          /* OnlyPermanentLeasesSupported */
                pm->u_lease = 0;
                u_request(ctx, U_ADD);
                return;
            }
            if ((code == 718 || code == 724 || code == 727) && pm->u_conflicts < 3) {
                /* Port taken (718), or must match the internal port (724). */
                pm->u_conflicts++;
                if (code == 724) {
                    u_fail(ctx, "router requires equal ports and ours is taken");
                    return;
                }
                pm->u_ext_port = (uint16_t)(20000 + pc_random_u64() % 40000);
                u_request(ctx, U_ADD);
                return;
            }
            snprintf(val, sizeof(val), "AddPortMapping refused (error %d)", code);
            u_fail(ctx, val);
        }
        return;
    default:
        return;
    }
}

static void ssdp_send(pierce_ctx *ctx)
{
    static const char *targets[] = {"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                                    "urn:schemas-upnp-org:service:WANIPConnection:1"};
    char m[300];
    for (int i = 0; i < 2; i++) {
        int n = snprintf(m, sizeof(m),
                         "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
                         "MX: 2\r\nST: %s\r\n\r\n",
                         targets[i]);
        pc_send_direct(ctx, &ctx->pm->ssdp, (const uint8_t *)m, (size_t)n);
    }
}

static void ssdp_input(pierce_ctx *ctx, const uint8_t *p, size_t len)
{
    pc_portmap *pm = ctx->pm;
    if (pm->u_state != U_DISCOVER) return;
    const char *s = (const char *)p, *loc = find_ci(s, len, "\nlocation:");
    if (!loc) return;
    loc += 10;
    while (loc < s + len && *loc == ' ') loc++;
    char url[300];
    size_t k = 0;
    while (loc + k < s + len && loc[k] != '\r' && loc[k] != '\n' && k < sizeof(url) - 1) {
        url[k] = loc[k];
        k++;
    }
    url[k] = 0;
    if (parse_http_url(url, &pm->u_http, pm->u_desc_path, sizeof(pm->u_desc_path)) < 0) return;
    pc_log(ctx, PIERCE_LOG_DEBUG, "UPnP: router found at %s", url);
    /* Our address on the router's LAN, for NewInternalClient. */
    if (!(ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP)) pal_route_source(&pm->u_http, &pm->lan_ip);
    u_request(ctx, U_DESC);
}

static void u_timers(pierce_ctx *ctx, uint64_t now)
{
    pc_portmap *pm = ctx->pm;
    switch (pm->u_state) {
    case U_DISCOVER:
        if (now >= pm->u_deadline_us) {
            pm->u_state = U_FAILED;      /* no UPnP router: quietly done */
            return;
        }
        if (now >= pm->u_next_us && pm->u_tries < 3) {
            ssdp_send(ctx);
            pm->u_tries++;
            pm->u_next_us = now + 1000000;
        }
        break;
    case U_DESC:
    case U_EXTIP:
    case U_ADD:
        if (pm->h_state != H_NONE && now >= pm->u_deadline_us) u_fail(ctx, "router stopped answering");
        break;
    case U_MAPPED:
        if (pm->u_refresh_us && now >= pm->u_refresh_us) u_request(ctx, U_ADD);
        break;
    default:
        break;
    }
}

static uint64_t u_next(const pc_portmap *pm)
{
    switch (pm->u_state) {
    case U_DISCOVER: return pm->u_tries < 3 ? PC_MIN(pm->u_next_us, pm->u_deadline_us) : pm->u_deadline_us;
    case U_DESC:
    case U_EXTIP:
    case U_ADD: return pm->u_deadline_us;
    case U_MAPPED: return pm->u_refresh_us;
    default: return 0;
    }
}

void pc_portmap_io(pierce_ctx *ctx)
{
    pc_portmap *pm = ctx->pm;
    if (!pm || pm->h_state == H_NONE) return;
    if (pm->h_state == H_CONNECTING) {
        int r = pal_tcp_connect_result(pm->h_sock);
        if (r < 0) {
            u_fail(ctx, "cannot connect to the router");
            return;
        }
        if (r == 0) return;
        pm->h_state = H_SENDING;
    }
    if (pm->h_state == H_SENDING) {
        while (pm->h_req_off < pm->h_req_len) {
            int n = pal_tcp_send(pm->h_sock, pm->h_req + pm->h_req_off, pm->h_req_len - pm->h_req_off);
            if (n == PIERCE_ERR_WOULD_BLOCK) return;
            if (n <= 0) {
                u_fail(ctx, "send to the router failed");
                return;
            }
            pm->h_req_off += (uint32_t)n;
        }
        pm->h_state = H_RECEIVING;
    }
    for (;;) {
        if (pm->h_resp_len >= HTTP_MAX) {
            u_fail(ctx, "router response too large");
            return;
        }
        int n = pal_tcp_recv(pm->h_sock, pm->h_resp + pm->h_resp_len, HTTP_MAX - pm->h_resp_len);
        if (n == PIERCE_ERR_WOULD_BLOCK) return;
        if (n < 0) {
            u_fail(ctx, "receive from the router failed");
            return;
        }
        if (n == 0) break;   /* Connection: close marks the end */
        pm->h_resp_len += (uint32_t)n;
    }
    uint32_t len = pm->h_resp_len;
    http_close(pm, ctx);
    char *body;
    size_t blen;
    int status = http_parse(pm->h_resp, len, &body, &blen);
    if (status < 0) {
        u_fail(ctx, "malformed HTTP response from the router");
        return;
    }
    u_response(ctx, status, body, blen);
}

uint32_t pc_portmap_wait_set(pierce_ctx *ctx, pal_pollfd *fds, int32_t *tags)
{
    pc_portmap *pm = ctx->pm;
    if (!pm || pm->h_state == H_NONE || pm->h_sock == PAL_INVALID_SOCK) return 0;
    fds[0].sock = pm->h_sock;
    fds[0].want_write = pm->h_state != H_RECEIVING;
    tags[0] = -3;
    return 1;
}

/* ===================================================================== */
/* Entry points                                                          */
/* ===================================================================== */

static void start(pierce_ctx *ctx, uint64_t now)
{
    pc_portmap *pm = ctx->pm;
    pm->started = 1;
    int builtin = !(ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP);
    /* Our primary IPv4 port: the bound socket, or the custom transport's
       declared local address. */
    pm->int_port = ctx->port4;
    if (!builtin)
        for (uint32_t i = 0; i < ctx->nlocal_addrs && !pm->int_port; i++)
            if (ctx->local_addrs[i].family == PIERCE_AF_INET) {
                pm->int_port = ctx->local_addrs[i].port;
                pm->lan_ip = ctx->local_addrs[i];
            }
    if (!pm->int_port) return;
    if (!pm->has_gw && builtin && pal_default_gateway(&pm->gw) == PIERCE_OK) {
        pm->gw.port = PMP_PORT;
        pm->has_gw = 1;
    }
    if (pm->has_gw) {
        if (builtin) pal_route_source(&pm->gw, &pm->lan_ip);
        pc_random(pm->nonce, sizeof(pm->nonce));
        pm->pmp_state = PMP_PCP;
        pm->pmp_next_us = now;
    }
    if (!pm->has_ssdp && builtin) {
        pierce_addr_parse("239.255.255.250:1900", &pm->ssdp);
        pm->has_ssdp = 1;
    }
    if (pm->has_ssdp) {
        pm->u_state = U_DISCOVER;
        pm->u_next_us = now;
        pm->u_deadline_us = now + SSDP_WINDOW_US;
    }
}

void pc_portmap_timers(pierce_ctx *ctx, uint64_t now)
{
    if (disabled(ctx) || !ensure(ctx)) return;
    if (!ctx->pm->started) start(ctx, now);
    pmp_timers(ctx, now);
    u_timers(ctx, now);
}

uint64_t pc_portmap_next(pierce_ctx *ctx)
{
    if (disabled(ctx)) return 0;
    if (!ctx->pm || !ctx->pm->started) return pc_now(ctx);   /* start on the next pass */
    uint64_t a = pmp_next(ctx->pm), b = u_next(ctx->pm);
    if (!a) return b;
    if (!b) return a;
    return PC_MIN(a, b);
}

int pc_portmap_input(pierce_ctx *ctx, const pierce_addr *src, const uint8_t *p, size_t len)
{
    pc_portmap *pm = ctx->pm;
    if (!pm || !pm->started) return 0;
    if (pm->has_gw && src->port == PMP_PORT && pc_addr_ip_eq(src, &pm->gw)) {
        pmp_input(ctx, p, len);
        return 1;
    }
    if (pm->u_state == U_DISCOVER && len > 12 && memcmp(p, "HTTP/1.1 200", 12) == 0) {
        ssdp_input(ctx, p, len);
        return 1;
    }
    return 0;
}

/* Best-effort cleanup at shutdown. PCP/NAT-PMP deletions are one datagram;
   the UPnP deletion is a short blocking request (bounded to ~0.5 s). */
void pc_portmap_free(pierce_ctx *ctx)
{
    pc_portmap *pm = ctx->pm;
    if (!pm) return;
    if (pm->pmp_state == PMP_MAPPED) {
        if (pm->pmp_proto == PMP_NATPMP) natpmp_send(ctx, 0);
        else pcp_send(ctx, 0);
    }
    http_close(pm, ctx);
    if (pm->u_state == U_MAPPED && !(ctx->flags & PIERCE_CFG_NO_BUILTIN_UDP)) {
        char req[4096];
        int n = build_delete(pm, req, sizeof(req));
        pal_sock s;
        if (n > 0 && pal_tcp_connect(&pm->u_http, &s) == PIERCE_OK) {
            pal_pollfd f;
            memset(&f, 0, sizeof(f));
            f.sock = s;
            f.want_write = 1;
            if (pal_wait(&f, 1, 250) > 0 && pal_tcp_connect_result(s) == 1 &&
                pal_tcp_send(s, req, (size_t)n) == n) {
                f.want_write = 0;
                pal_wait(&f, 1, 250);   /* let the router read it before we hang up */
            }
            pal_sock_close(s);
        }
    }
    pc_free(&ctx->alloc, pm->h_resp);
    pc_free(&ctx->alloc, pm);
    ctx->pm = NULL;
}
