package ru.apidefender.scanners;

import com.fasterxml.jackson.databind.JsonNode;
import ru.apidefender.core.http.HttpClient;
import ru.apidefender.core.log.JsonlLogger;
import ru.apidefender.core.report.ReportModel;

import java.util.List;
import java.util.concurrent.CompletableFuture;

public interface SPI {
    String getCategory();
    CompletableFuture<Void> run(ScanContext ctx);

    class ScanContext {
        // CLI override base URL (if provided), otherwise null
        public final String overrideBaseUrl;
        // Default base URL from OpenAPI (first server) or fallback
        public final String defaultBaseUrl;
        // Optional mapping pathTemplate -> baseUrl (built from original specs)
        public final java.util.Map<String, String> pathBaseUrls;
        public final HttpClient http;
        public final JsonlLogger log;
        public final ReportModel report;
        public final boolean debug;
        public final JsonNode openapi;
        public final List<String> endpoints;
        public final String preset; // fast/full/aggressive
        public final int idorMax;
        public final int injectionOps;
        public final int rateBurst;
        public final String exploitDepth; // low|med|high
        public final int maxExploitOps;
        public final boolean safetySkipDelete;
        public interface TraceSaver { String save(String url, String method, String reqBody, okhttp3.Response resp); }
        public final TraceSaver traceSaver;

        public final List<String> publicPaths;
        public final boolean allowCorsWildcardPublic;
        public final java.util.Map<String, java.util.List<String>> discoveredIds;

        public ScanContext(String overrideBaseUrl,
                           String defaultBaseUrl,
                           java.util.Map<String, String> pathBaseUrls,
                           HttpClient http, JsonlLogger log, ReportModel report,
                           boolean debug, JsonNode openapi, List<String> endpoints, String preset,
                           int idorMax, int injectionOps, int rateBurst, TraceSaver traceSaver,
                           List<String> publicPaths, boolean allowCorsWildcardPublic,
                           String exploitDepth, int maxExploitOps, boolean safetySkipDelete) {
            this.overrideBaseUrl = overrideBaseUrl;
            this.defaultBaseUrl = defaultBaseUrl;
            this.pathBaseUrls = pathBaseUrls != null ? pathBaseUrls : java.util.Collections.emptyMap();
            this.http = http;
            this.log = log;
            this.report = report;
            this.debug = debug;
            this.openapi = openapi;
            this.endpoints = endpoints;
            this.preset = preset;
            this.idorMax = idorMax;
            this.injectionOps = injectionOps;
            this.rateBurst = rateBurst;
            this.traceSaver = traceSaver;
            this.publicPaths = publicPaths;
            this.allowCorsWildcardPublic = allowCorsWildcardPublic;
            this.exploitDepth = exploitDepth;
            this.maxExploitOps = maxExploitOps;
            this.safetySkipDelete = safetySkipDelete;
            this.discoveredIds = java.util.Collections.synchronizedMap(new java.util.HashMap<>());
        }

        /**
         * Обёртка над HttpClient, учитывающая все запросы в общей телеметрии.
         */
        public okhttp3.Response trackedRequest(String method, String url,
                                               java.util.Map<String, String> headers,
                                               okhttp3.RequestBody body) throws java.io.IOException {
            long t0 = System.nanoTime();
            okhttp3.Response resp = http.request(method, url, headers, body);
            long dt = (System.nanoTime() - t0) / 1_000_000L;
            synchronized (report.telemetry) {
                report.telemetry.requestsTotal++;
                report.telemetry.avgLatencyMs += dt;
            }
            return resp;
        }

        public void addDiscoveredId(String key, String value) {
            if (key == null || value == null || value.isBlank()) return;
            String k = key.toLowerCase(java.util.Locale.ROOT);
            discoveredIds.computeIfAbsent(k, ignore -> new java.util.ArrayList<>());
            java.util.List<String> list = discoveredIds.get(k);
            if (!list.contains(value)) list.add(value);
        }

        public String url(String path) {
            String base = resolveBaseUrl(path);
            String b = base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
            String resolved = resolvePathParams(path);
            return b + (resolved.startsWith("/") ? resolved : "/" + resolved);
        }

        private String resolveBaseUrl(String path) {
            // CLI override has highest priority
            if (overrideBaseUrl != null && !overrideBaseUrl.isBlank()) {
                return overrideBaseUrl;
            }
            if (pathBaseUrls != null && !pathBaseUrls.isEmpty()) {
                String p = path == null ? "" : (path.startsWith("/") ? path : "/" + path);
                String direct = pathBaseUrls.get(p);
                if (direct != null && !direct.isBlank()) return direct;
                String best = null;
                int bestLen = -1;
                for (java.util.Map.Entry<String, String> e : pathBaseUrls.entrySet()) {
                    String key = e.getKey();
                    if (key == null || key.isBlank()) continue;
                    String base = e.getValue();
                    if (base == null || base.isBlank()) continue;
                    String prefix = key;
                    int idx = key.indexOf('{');
                    if (idx >= 0) prefix = key.substring(0, idx);
                    if (prefix.isEmpty()) continue;
                    if (p.startsWith(prefix) && prefix.length() > bestLen) {
                        bestLen = prefix.length();
                        best = base;
                    }
                }
                if (best != null) return best;
            }
            return (defaultBaseUrl != null && !defaultBaseUrl.isBlank())
                    ? defaultBaseUrl
                    : "http://localhost:8080";
        }

        private String resolvePathParams(String path) {
            if (path == null || path.isEmpty()) return "";
            StringBuilder sb = new StringBuilder();
            int i = 0;
            while (i < path.length()) {
                int start = path.indexOf('{', i);
                if (start < 0) {
                    sb.append(path.substring(i));
                    break;
                }
                int end = path.indexOf('}', start);
                if (end < 0) {
                    sb.append(path.substring(i));
                    break;
                }
                sb.append(path, i, start);
                String name = path.substring(start + 1, end).toLowerCase(java.util.Locale.ROOT);
                sb.append(sampleValue(name));
                i = end + 1;
            }
            return sb.toString();
        }

        private String sampleValue(String name) {
            if (name.contains("externalaccount")) return "0dbcb7ee-6c59-483b-966a-44d11557665b";
            if (name.contains("account")) return "1001";
            if (name.contains("payment")) return "9001";
            if (name.contains("consent")) return "consent-1001";
            if (name.contains("offer")) return "offer-1001";
            if (name.contains("application")) return "app-1001";
            if (name.contains("lead")) return "lead-1001";
            if (name.contains("client")) return "team163";
            if (name.contains("token")) return "tok_sample";
            if (name.contains("id")) return "123";
            return "1";
        }
    }
}
