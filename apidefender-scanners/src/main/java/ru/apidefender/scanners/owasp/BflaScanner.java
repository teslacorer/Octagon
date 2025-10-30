package ru.apidefender.scanners.owasp;

import okhttp3.RequestBody;
import okhttp3.Response;
import ru.apidefender.core.http.HttpClient;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;

public class BflaScanner implements SPI {
    @Override public String getCategory() { return "BFLA"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            List<String> sensitiveHints = List.of("admin","internal","manage","config","users","roles","priv","secure");
            int max = switch (ctx.preset) { case "fast" -> 6; case "aggressive" -> 24; default -> 12; };
            int tested = 0;
            for (String p : ctx.endpoints) {
                if (tested >= max) break;
                boolean sensitive = false;
                String low = p.toLowerCase();
                for (String h : sensitiveHints) if (low.contains(h)) { sensitive = true; break; }
                if (!sensitive) continue;
                // target only modifying methods where present
                List<String> methods = List.of("POST","PUT","PATCH","DELETE");
                for (String m : methods) {
                    if (!ctx.openapi.path("paths").path(p).has(m.toLowerCase())) continue;
                    tested++;
                    String url = ctx.url(p);
                    // try without token
                    try (Response rNo = new HttpClient(java.time.Duration.ofSeconds(10), null, true)
                            .request(m, url, Map.of("Content-Type","application/json"), sampleBody())) {
                        int codeNo = rNo.code();
                        if (codeNo >= 200 && codeNo < 300) {
                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                            si.id = UUID.randomUUID().toString();
                            si.category = getCategory();
                            si.severity = "High";
                            si.endpoint = p;
                            si.method = m;
                            si.description = "Доступ к потенциально привилегированной функции без авторизации";
                            si.evidence = "Статус без токена="+codeNo;
                            si.impact = "Обход ограничений уровня функции";
                            si.recommendation = "Требовать авторизацию/роль для админских операций";
                            si.traceRef = ctx.traceSaver.save(url, m, "{}", rNo);
                            synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                        }
                    } catch (Exception ignored) {}
                }
            }
        });
    }

    private RequestBody sampleBody() {
        return RequestBody.create("{}".getBytes(StandardCharsets.UTF_8));
    }
}

