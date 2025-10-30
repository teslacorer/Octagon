package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class RateLimitScanner implements SPI {
    @Override public String getCategory() { return "RateLimit"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            if (ctx.endpoints.isEmpty()) return;
            String p = ctx.endpoints.get(0); // тестируем первый доступный путь
            String url = ctx.url(p);
            int burst = ctx.rateBurst;
            int code429 = 0; boolean hasHeaders = false;
            for (int i=0;i<burst;i++) {
                try (Response r = ctx.http.request("GET", url, null, null)) {
                    if (r.code() == 429) code429++;
                    if (r.header("X-RateLimit-Remaining") != null || r.header("Retry-After") != null) hasHeaders = true;
                } catch (Exception ignored) {}
            }
            if (code429 == 0 && !hasHeaders) {
                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                si.id = UUID.randomUUID().toString();
                si.category = getCategory();
                si.severity = "Low";
                si.endpoint = p;
                si.method = "GET";
                si.description = "Отсутствуют признаки ограничений по частоте запросов";
                si.evidence = "Нет 429/RateLimit заголовков";
                si.impact = "Риск перебора/брютфорса";
                si.recommendation = "Ввести ограничения по частоте или капчу";
                si.traceRef = "ratelimit-checked-"+burst;
                synchronized (ctx.report.security){ ctx.report.security.add(si);} 
            }
        });
    }
}
