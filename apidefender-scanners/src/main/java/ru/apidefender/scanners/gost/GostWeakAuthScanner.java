package ru.apidefender.scanners.gost;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * WeakAuth: проверка обхода авторизации (no‑auth / bad‑auth) на чувствительных банковских эндпоинтах.
 */
public class GostWeakAuthScanner implements SPI {
    @Override
    public String getCategory() {
        return "GostWeakAuth";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                int maxEndpoints = switch (ctx.preset) {
                    case "fast" -> 6;
                    case "aggressive" -> 18;
                    default -> 10;
                };

                int epCount = 0;
                for (String path : ctx.endpoints) {
                    if (epCount++ >= maxEndpoints) break;
                    if (!looksSensitive(path)) continue;
                    String method = chooseMethod(ctx, path);
                    if (method == null) continue;
                    String url = ctx.url(path);

                    // no‑auth: отправляем пустой Authorization, перекрывая default Bearer из HttpClient
                    Map<String, String> noAuth = Map.of("Authorization", "");
                    try (Response r = ctx.trackedRequest(method, url, noAuth, null)) {
                        int code = r.code();
                        if (code >= 200 && code < 300) {
                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                            si.id = UUID.randomUUID().toString();
                            si.category = getCategory();
                            si.severity = "High";
                            si.endpoint = path;
                            si.method = method;
                            si.description = "Обнаружена слабая авторизация: чувствительный эндпоинт доступен без валидного токена (no‑auth).";
                            si.evidence = method + " " + path + " без валидного Authorization => " + code;
                            si.impact = "Злоумышленник может вызывать банковский эндпоинт (счета, карты, токены) без корректной аутентификации.";
                            si.recommendation = "Требовать обязательный Bearer JWT/токен для всех чувствительных эндпоинтов, возвращать 401/403 при его отсутствии.";
                            si.traceRef = ctx.traceSaver.save(url, method, null, r);
                            synchronized (ctx.report.security) {
                                ctx.report.security.add(si);
                            }
                        }
                    } catch (Exception ignored) {
                    }

                    // bad‑auth: заведомо некорректный токен
                    try {
                        Map<String, String> bad = Map.of("Authorization", "Bearer invalid.invalid.invalid");
                        try (Response rBad = ctx.trackedRequest(method, url, bad, null)) {
                            int codeBad = rBad.code();
                            if (codeBad >= 200 && codeBad < 300) {
                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                si.id = UUID.randomUUID().toString();
                                si.category = getCategory();
                                si.severity = "High";
                                si.endpoint = path;
                                si.method = method;
                                si.description = "Обнаружена слабая авторизация: эндпоинт принимает заведомо некорректный токен (bad‑auth).";
                                si.evidence = method + " " + path + " + Authorization: Bearer invalid => " + codeBad;
                                si.impact = "Возможен обход аутентификации с произвольным/поддельным токеном и доступ к данным других клиентов.";
                                si.recommendation = "Проверять подпись и срок действия JWT/токена на сервере, отклонять любые невалидные значения (401/403).";
                                si.traceRef = ctx.traceSaver.save(url, method, null, rBad);
                                synchronized (ctx.report.security) {
                                    ctx.report.security.add(si);
                                }
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            } catch (Exception ignored) {
            }
        });
    }

    private boolean looksSensitive(String path) {
        String p = path.toLowerCase(Locale.ROOT);
        return p.contains("account")
                || p.contains("card")
                || p.contains("balance")
                || p.contains("payment")
                || p.contains("transfer")
                || p.contains("credential")
                || p.contains("token")
                || p.contains("deposit")
                || p.contains("loan")
                || p.contains("credit")
                || p.contains("cvv")
                || p.contains("status")
                || p.contains("close")
                || p.contains("pin");
    }

    private String chooseMethod(ScanContext ctx, String path) {
        var node = ctx.openapi.path("paths").path(path);
        for (String m : List.of("get", "post", "put", "patch", "delete")) {
            if (node.has(m)) return m.toUpperCase(Locale.ROOT);
        }
        return null;
    }
}
