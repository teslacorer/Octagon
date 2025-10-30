package ru.apidefender.scanners.simple;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class SecurityHeadersScanner implements SPI {
    private static final List<String> REQUIRED = List.of(
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy",
            "Cache-Control"
    );

    @Override public String getCategory() { return "SecurityHeaders"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try (Response r = ctx.http.request("GET", ctx.url("/"), null, null)) {
                for (String h : REQUIRED) {
                    if (r.header(h) == null) {
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = "Low";
                        si.endpoint = "/";
                        si.method = "GET";
                        si.description = "Отсутствует заголовок " + h;
                        si.evidence = h + ": <none>";
                        si.impact = "Пониженная защита браузера";
                        si.recommendation = "Добавить заголовок в ответы";
                        si.traceRef = ctx.traceSaver.save(ctx.url("/"), "GET", null, r);
                        ctx.report.security.add(si);
                    }
                }
            } catch (Exception ignored) { }
        });
    }
}
