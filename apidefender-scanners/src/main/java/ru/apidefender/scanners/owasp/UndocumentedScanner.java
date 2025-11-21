package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Поиск потенциально чувствительных "служебных" эндпоинтов, не описанных в OpenAPI.
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
                    "/swagger-ui.html", "/swagger", "/swagger/index.html", "/swagger/ui/index",
                    "/swagger/swagger-ui.html", "/swagger-ui/index.html", "/swagger-ui/swagger-ui.js",
                    "/api/swagger-ui.html", "/api-docs/swagger.json", "/api-docs/swagger.yaml",
                    "/api/swagger.json", "/api/swagger.yaml", "/swagger.json", "/swagger.yaml",
                    "/v3/api-docs", "/v3/api-docs/ui", "/openapi.json", "/api-docs", "/api-doc",
                    "/docs", "/docs/index.html", "/apidocs", "/apidocs/index.html",
                    "/webjars/swagger-ui/index.html", "/swagger-resources", "/swagger-resources/configuration/ui",
                    "/swagger-resources/configuration/security", "/graphql"
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
                    // Считаем эндпоинт "живым" только если это 2xx, 401 или 403 (т.е. существует и/или требует auth).
                    // 429 (Rate Limit) не считаем доказательством существования полезного сервиса.
                    if ((code >= 200 && code < 300) || code == 401 || code == 403) {
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = (code >= 200 && code < 300) ? "Medium" : "Low";
                        si.endpoint = p;
                        si.method = "GET";
                        si.description = "Обнаружен потенциально чувствительный служебный эндпоинт вне OpenAPI.";
                        si.evidence = "GET "+p+" => "+code;
                        si.impact = "Поверхность атаки шире, чем описано в контракте; возможны дополнительные векторы.";
                        si.recommendation = "Ограничить доступ, добавить аутентификацию/авторизацию или скрыть эндпоинт; при необходимости описать его в OpenAPI.";
                        si.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                        synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                    }
                } catch (Exception ignored) {}
            }
        });
    }
}

