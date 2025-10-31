package ru.apidefender.scanners.simple;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class CorsHeadersScanner implements SPI {
    @Override
    public String getCategory() {
        return "CORS";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                // проверяем корень и до 3 публичных путей
                java.util.List<String> toCheck = new java.util.ArrayList<>();
                toCheck.add("/");
                int added = 0;
                for (String p : ctx.publicPaths) {
                    if (added >= 3)
                        break;
                    toCheck.add(p);
                    added++;
                }
                for (String path : toCheck) {
                    String url = ctx.url(path);
                    try (Response r = ctx.http.request("GET", url, null, null)) {
                        String acao = r.header("Access-Control-Allow-Origin");
                        boolean wildcard = "*".equals(acao);
                        boolean isPublic = ctx.publicPaths.stream().anyMatch(pref -> path.startsWith(pref));
                        boolean issue = (acao == null) || (wildcard && !(ctx.allowCorsWildcardPublic && isPublic));
                        if (issue) {
                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                            si.id = UUID.randomUUID().toString();
                            si.category = getCategory();
                            si.severity = "Medium";
                            si.endpoint = path;
                            si.method = "GET";
                            si.description = acao == null ? "Отсутствует заголовок Access-Control-Allow-Origin"
                                    : "Access-Control-Allow-Origin = * без явной публичности";
                            si.evidence = "Access-Control-Allow-Origin: " + acao;
                            si.impact = "Риск междоменного доступа к ресурсам";
                            si.recommendation = "Установить конкретные доверенные источники или явно пометить путь публичным";
                            si.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                            ctx.report.security.add(si);
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        });
    }
}
