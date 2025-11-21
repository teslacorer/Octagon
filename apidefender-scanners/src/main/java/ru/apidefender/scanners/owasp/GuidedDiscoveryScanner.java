package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Расширенный поиск недекларированных возможностей: строит словарь на основе сегментов OpenAPI и общих путей.
 * Безопасные GET-запросы, без модификаций состояния.
 */
public class GuidedDiscoveryScanner implements SPI {
    @Override public String getCategory() { return "Undocumented"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            Set<String> known = new HashSet<>();
            ctx.openapi.path("paths").fieldNames().forEachRemaining(known::add);

            Set<String> candidates = new LinkedHashSet<>();
            // базовые известные пути
            candidates.addAll(List.of("/admin", "/admin/login", "/admin/config", "/admin/health",
                    "/metrics", "/actuator", "/actuator/health", "/actuator/env", "/debug",
                    "/swagger", "/swagger-ui.html", "/v3/api-docs", "/graphql"));

            // сегменты из OpenAPI + типовые суффиксы
            for (String p : known) {
                for (String seg : p.split("/")) {
                    if (seg.isBlank() || seg.startsWith("{")) continue;
                    candidates.add("/" + seg + "/debug");
                    candidates.add("/" + seg + "/internal");
                    candidates.add("/" + seg + "/metrics");
                    candidates.add("/" + seg + "/health");
                    candidates.add("/" + seg + "/status");
                }
            }

            int max = switch (ctx.preset) { case "aggressive" -> 50; case "fast" -> 15; default -> 30; };
            int tested = 0;
            for (String p : candidates) {
                if (tested >= max) break;
                if (known.contains(p)) continue;
                tested++;
                String url = ctx.url(p);
                try (Response r = ctx.http.request("GET", url, null, null)) {
                    int code = r.code();
                    if ((code >= 200 && code < 300) || code == 401 || code == 403 || code == 429) {
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = (code >= 200 && code < 300) ? "Medium" : "Low";
                        si.endpoint = p;
                        si.method = "GET";
                        si.description = "Найдён недокументированный эндпоинт (guided)";
                        si.evidence = "GET "+p+" => "+code;
                        si.impact = "Поверхность атаки шире заявленной спецификации";
                        si.recommendation = "Задокументировать/закрыть скрытый путь или ограничить доступ";
                        si.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                        synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                    }
                } catch (Exception ignored) {}
            }
        });
    }
}
