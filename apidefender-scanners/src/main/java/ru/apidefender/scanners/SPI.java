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
        public final String baseUrl;
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

        public ScanContext(String baseUrl, HttpClient http, JsonlLogger log, ReportModel report,
                           boolean debug, JsonNode openapi, List<String> endpoints, String preset,
                           int idorMax, int injectionOps, int rateBurst, TraceSaver traceSaver,
                           List<String> publicPaths, boolean allowCorsWildcardPublic,
                           String exploitDepth, int maxExploitOps, boolean safetySkipDelete) {
            this.baseUrl = baseUrl;
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
        }

        public String url(String path) {
            String b = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
            String resolved = resolvePathParams(path);
            return b + (resolved.startsWith("/") ? resolved : "/" + resolved);
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

