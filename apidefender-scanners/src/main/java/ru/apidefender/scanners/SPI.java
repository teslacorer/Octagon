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
            this.baseUrl = baseUrl; this.http = http; this.log = log; this.report = report; this.debug = debug;
            this.openapi = openapi; this.endpoints = endpoints; this.preset = preset;
            this.idorMax = idorMax; this.injectionOps = injectionOps; this.rateBurst = rateBurst;
            this.traceSaver = traceSaver;
            this.publicPaths = publicPaths;
            this.allowCorsWildcardPublic = allowCorsWildcardPublic;
            this.exploitDepth = exploitDepth;
            this.maxExploitOps = maxExploitOps;
            this.safetySkipDelete = safetySkipDelete;
        }
        public String url(String path){
            String b = baseUrl.endsWith("/")? baseUrl.substring(0, baseUrl.length()-1): baseUrl;
            return b + (path.startsWith("/")? path: "/"+path);
        }
    }
}
