package ru.apidefender.scanners.gost;

import okhttp3.MediaType;
import okhttp3.RequestBody;
import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * GostInjectionScanner: проверка на базовые SQL/инъекции в тело и заголовки.
 */
public class GostInjectionScanner implements SPI {
    private static final MediaType JSON = MediaType.parse("application/json");

    @Override
    public String getCategory() {
        return "GostInjection";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                int maxEndpoints = switch (ctx.preset) {
                    case "fast" -> 4;
                    case "aggressive" -> 10;
                    default -> 6;
                };
                int maxOps = switch (ctx.preset) {
                    case "fast" -> 40;
                    case "aggressive" -> 160;
                    default -> 80;
                };

                String[] payloads = {
                        "' OR '1'='1",
                        "\" OR \"1\"=\"1",
                        "1 OR 1=1",
                        "${jndi:ldap://example.com/a}",
                        "'; DROP TABLE test; --"
                };

                int used = 0;
                int epCount = 0;
                for (String path : ctx.endpoints) {
                    if (epCount++ >= maxEndpoints) break;
                    String method = chooseMethod(ctx, path);
                    if (method == null) continue;
                    String url = ctx.url(path);

                    // Инъекции через тело запроса
                    for (String p : payloads) {
                        if (used >= maxOps) break;
                        String body = "{\"test\":\"" + p.replace("\"", "\\\"") + "\"}";
                        RequestBody rb = RequestBody.create(body, JSON);
                        try (Response r = ctx.trackedRequest(method, url, null, rb)) {
                            used++;
                            int code = r.code();
                            String respBody = safeBody(r);
                            if ((code >= 500 || looksLikeErrorTrace(respBody)) && code != 429) {
                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                si.id = UUID.randomUUID().toString();
                                si.category = getCategory();
                                si.severity = code >= 500 ? "High" : "Medium";
                                si.endpoint = path;
                                si.method = method;
                                si.description = "Обнаружена возможная инъекция через тело запроса: приложение вернуло 5xx или подробный stack trace на вредоносный payload.";
                                si.evidence = "Payload=" + p + ", status=" + code;
                                si.impact = "Потенциальное исполнение произвольного кода или раскрытие внутренней информации за счёт обработки непрофильтрованных данных в SQL, шаблонах или бизнес-логике.";
                                si.recommendation = "Использовать параметризацию (prepared statements), строгую валидацию и экранирование входных данных, а также отключить вывод подробных stack trace во внешние ответы.";
                                si.traceRef = ctx.traceSaver.save(url, method, body, r);
                                synchronized (ctx.report.security) {
                                    ctx.report.security.add(si);
                                }
                            }
                        } catch (Exception ignored) {
                        }
                    }
                    if (used >= maxOps) break;

                    // Инъекции через заголовок Correlation-ID
                    if (used >= maxOps) break;
                    for (String p : payloads) {
                        if (used >= maxOps) break;
                        java.util.Map<String, String> headers = java.util.Map.of("Correlation-ID", p);
                        try (Response r = ctx.trackedRequest(method, url, headers, null)) {
                            used++;
                            int code = r.code();
                            String respBody = safeBody(r);
                            if ((code >= 500 || looksLikeErrorTrace(respBody)) && code != 429) {
                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                si.id = UUID.randomUUID().toString();
                                si.category = getCategory();
                                si.severity = code >= 500 ? "High" : "Medium";
                                si.endpoint = path;
                                si.method = method;
                                si.description = "Обнаружена возможная инъекция через заголовок Correlation-ID: приложение вернуло 5xx или подробный stack trace на вредоносное значение заголовка.";
                                si.evidence = "Correlation-ID=" + p + ", status=" + code;
                                si.impact = "Потенциальное выполнение произвольного кода или утечка внутренней информации за счёт использования Correlation-ID в логике приложения, SQL-запросах или шаблонах.";
                                si.recommendation = "Не использовать Correlation-ID как доверенный пользовательский ввод, валидировать и нормализовать его, отделить диагностические идентификаторы от бизнес-логики и отключить детальные stack trace во внешних ответах.";
                                si.traceRef = ctx.traceSaver.save(url, method, null, r);
                                synchronized (ctx.report.security) {
                                    ctx.report.security.add(si);
                                }
                            }
                        } catch (Exception ignored) {
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        });
    }

    private String chooseMethod(ScanContext ctx, String path) {
        var node = ctx.openapi.path("paths").path(path);
        for (String m : List.of("post", "put", "patch", "get")) {
            if (node.has(m)) return m.toUpperCase(Locale.ROOT);
        }
        return null;
    }

    private String safeBody(Response r) {
        try {
            return r.peekBody(40_000).string();
        } catch (Exception ignored) {
            return "";
        }
    }

    private boolean looksLikeErrorTrace(String body) {
        String b = body.toLowerCase(Locale.ROOT);
        return b.contains("exception")
                || b.contains("stacktrace")
                || b.contains("trace:")
                || b.contains("sqlsyntaxerrorexception")
                || b.contains("syntax error");
    }
}

