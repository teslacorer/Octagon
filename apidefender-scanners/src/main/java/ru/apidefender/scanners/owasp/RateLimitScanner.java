package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class RateLimitScanner implements SPI {
    @Override
    public String getCategory() {
        return "RateLimit";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            if (ctx.endpoints.isEmpty()) return;
            int maxTargets = switch (ctx.preset) { case "aggressive" -> 5; case "fast" -> 1; default -> 3; };
            int tested = 0;
            for (String p : ctx.endpoints) {
                if (tested >= maxTargets) break;
                if (!ctx.openapi.path("paths").path(p).has("get")) continue;
                tested++;
                String url = ctx.url(p);
                int burst = ctx.rateBurst;
                int code429 = 0;
                boolean hasHeaders = false;
                int success = 0;
                for (int i = 0; i < burst; i++) {
                    try (Response r = ctx.http.request("GET", url, null, null)) {
                        int code = r.code();
                        if (code >= 200 && code < 300) success++;
                        if (code == 429) code429++;
                        if (r.header("X-RateLimit-Remaining") != null || r.header("Retry-After") != null) hasHeaders = true;
                    } catch (Exception ignored) {}
                }
                if (success == 0) continue;
                if (code429 == 0 && !hasHeaders) {
                    ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                    si.id = UUID.randomUUID().toString();
                    si.category = getCategory();
                    si.severity = "Low";
                    si.endpoint = p;
                    si.method = "GET";
                    si.description = "Отсутствуют признаки ограничений по частоте запросов";
                    si.evidence = "Путь="+p+", burst="+burst+", 429="+code429+", rate-limit headers="+hasHeaders;
                    si.impact = "Риск перебора/брютфорса";
                    si.recommendation = "Добавить rate limiting (429/Retry-After, X-RateLimit-*) на публичных GET";
                    si.traceRef = "ratelimit-checked-" + burst;
                    synchronized (ctx.report.security) {
                        ctx.report.security.add(si);
                    }
                }
            }
        });
    }
}
