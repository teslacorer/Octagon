package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.http.HttpClient;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class WeakAuthScanner implements SPI {
    @Override public String getCategory() { return "WeakAuth"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                int max = switch (ctx.preset) { case "fast" -> 3; case "aggressive" -> 12; default -> 6; };
                int i = 0;
                java.util.List<String> methodOrder = java.util.List.of("GET","POST","PUT","PATCH","DELETE");
                for (String p : ctx.endpoints) {
                    if (i++ >= max) break;
                    String url = ctx.url(p);
                    String method = "GET";
                    for (String m : methodOrder) {
                        if (ctx.openapi.path("paths").path(p).has(m.toLowerCase())) { method = m; break; }
                    }
                    try (Response r = new HttpClient(java.time.Duration.ofSeconds(10), null, true)
                            .request(method, url, null, null)) {
                        int code = r.code();
                        if (code >=200 && code <300) {
                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                            si.id = UUID.randomUUID().toString();
                            si.category = getCategory();
                            si.severity = "Medium";
                            si.endpoint = p;
                            si.method = method;
                            si.description = "Доступ без авторизации ("+method+")";
                            si.evidence = method+" => "+code+" без токена";
                            si.impact = "Потенциальная утечка данных";
                            si.recommendation = "Требовать авторизацию для чувствительных ресурсов";
                            si.traceRef = ctx.traceSaver.save(url, method, null, r);
                            synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                        }
                    } catch (Exception ignored) {}

                    // Принимается ли неверный/поддельный токен?
                    try {
                        Map<String,String> bad = new HashMap<>();
                        bad.put("Authorization", "Bearer invalid.invalid.invalid");
                        try (Response rBad = ctx.http.request(method, url, bad, null)) {
                            int codeBad = rBad.code();
                            if (codeBad >= 200 && codeBad < 300) {
                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                si.id = UUID.randomUUID().toString();
                                si.category = getCategory();
                                si.severity = "High";
                                si.endpoint = p;
                                si.method = method;
                                si.description = "Слабая проверка токена: принят заведомо неверный JWT";
                                si.evidence = method + " + Authorization: Bearer invalid => "+codeBad;
                                si.impact = "Обход аутентификации";
                                si.recommendation = "Проверять подпись/валидность токена, обрабатывать истекшие/поддельные токены";
                                si.traceRef = ctx.traceSaver.save(url, method, null, rBad);
                                synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                            }
                        }
                    } catch (Exception ignored) {}
                }
            } catch (Exception ignored) {}
        });
    }
}
