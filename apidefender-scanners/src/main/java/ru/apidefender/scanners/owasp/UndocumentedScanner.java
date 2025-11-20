package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Поиск недокументированных/скрытых эндпоинтов по словарю популярных путей.
 */
public class UndocumentedScanner implements SPI {
    @Override public String getCategory() { return "Undocumented"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            List<String> wordlist = new ArrayList<>(List.of(
                    "/health", "/status", "/metrics", "/actuator", "/actuator/health", "/actuator/env",
                    "/admin", "/admin/users", "/admin/login", "/admin/config",
                    "/internal", "/internal/metrics", "/internal/health",
                    "/swagger-ui.html", "/swagger", "/docs", "/v3/api-docs", "/openapi.json", "/graphql"
            ));
            // skip those already defined in OpenAPI
            wordlist.removeIf(p -> ctx.openapi.path("paths").has(p));

            int max = switch (ctx.preset) { case "fast" -> 10; case "aggressive" -> 40; default -> 20; };
            int tested = 0;
            for (String p : wordlist) {
                if (tested >= max) break;
                tested++;
                String url = ctx.url(p);
                try (Response r = ctx.http.request("GET", url, null, null)) {
                    int code = r.code();
                    if (code >= 200 && code < 300) {
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = "Medium";
                        si.endpoint = p;
                        si.method = "GET";
                        si.description = "Найдён недокументированный эндпоинт";
                        si.evidence = "GET "+p+" => "+code;
                        si.impact = "Поверхност атаки шире заявленной спецификации";
                        si.recommendation = "Задокументировать/закрыть скрытый путь или ограничить доступ";
                        si.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                        synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                    }
                } catch (Exception ignored) {}
            }
        });
    }
}
