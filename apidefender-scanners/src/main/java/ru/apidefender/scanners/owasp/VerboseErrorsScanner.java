package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class VerboseErrorsScanner implements SPI {
    @Override public String getCategory() { return "VerboseErrors"; }

    private static final List<String> SIGNS = List.of(
            "Exception:", "Stack trace", "NullPointerException", "IllegalArgumentException", "trace:\n"
    );

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            for (String p : ctx.endpoints) {
                String url = ctx.url(p + (p.contains("?")? "&": "?") + "_malformed=\uDC00");
                try (Response r = ctx.http.request("GET", url, null, null)) {
                    if (r.code() >= 500) {
                        String body = r.peekBody(200_000).string();
                        boolean verbose = SIGNS.stream().anyMatch(body::contains);
                        if (verbose) {
                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                            si.id = UUID.randomUUID().toString();
                            si.category = getCategory();
                            si.severity = "Low";
                            si.endpoint = p;
                            si.method = "GET";
                            si.description = "Многословные ошибки сервера (детали исключений)";
                            si.evidence = body.length()>300? body.substring(0,300): body;
                            si.impact = "Раскрытие внутренних деталей реализации";
                            si.recommendation = "Скрывать детали ошибок, использовать дружественные сообщения";
                            si.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                            synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                        }
                    }
                } catch (Exception ignored) {}
            }
        });
    }
}
