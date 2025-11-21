package ru.apidefender.scanners.gost;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * ExcessiveData‑сканер: ищет потенциально избыточные/чувствительные поля в ответах.
 */
public class GostExcessiveDataScanner implements SPI {
    @Override
    public String getCategory() {
        return "GostExcessiveData";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                int maxEndpoints = switch (ctx.preset) {
                    case "fast" -> 8;
                    case "aggressive" -> 35;
                    default -> 18;
                };

                ObjectMapper om = new ObjectMapper();
                int epCount = 0;
                for (String path : ctx.endpoints) {
                    if (epCount++ >= maxEndpoints) break;
                    String method = "GET";
                    String url = ctx.url(path);
                    try (Response r = ctx.trackedRequest(method, url, null, null)) {
                        int code = r.code();
                        if (code < 200 || code >= 300) continue;
                        String body = r.peekBody(80_000).string();
                        if (body == null || body.isBlank()) continue;
                        JsonNode root;
                        try {
                            root = om.readTree(body);
                        } catch (Exception ignored) {
                            continue;
                        }
                        List<String> suspicious = new ArrayList<>();
                        collectSuspiciousFields(root, "", suspicious);
                        if (!suspicious.isEmpty()) {
                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                            si.id = UUID.randomUUID().toString();
                            si.category = getCategory();
                            si.severity = "Medium";
                            si.endpoint = path;
                            si.method = method;
                            si.description = "Ответ содержит потенциально избыточные или чувствительные поля.";
                            si.evidence = "Подозрительные поля: " + String.join(", ", suspicious);
                            si.impact = "Клиент может получить больше данных, чем необходимо (PII/балансы/идентификаторы).";
                            si.recommendation = "Ограничить состав полей до минимально необходимого для сценария, скрывать PII.";
                            si.traceRef = ctx.traceSaver.save(url, method, null, r);
                            synchronized (ctx.report.security) {
                                ctx.report.security.add(si);
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            } catch (Exception ignored) {
            }
        });
    }

    private void collectSuspiciousFields(JsonNode node, String prefix, List<String> out) {
        if (node == null) return;
        if (node.isObject()) {
            Iterator<String> it = node.fieldNames();
            while (it.hasNext()) {
                String field = it.next();
                String path = prefix.isEmpty() ? field : prefix + "." + field;
                JsonNode v = node.get(field);
                if (looksSensitiveKey(field) || looksSensitiveValue(v)) {
                    out.add(path);
                }
                collectSuspiciousFields(v, path, out);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                collectSuspiciousFields(node.get(i), prefix + "[" + i + "]", out);
            }
        }
    }

    private boolean looksSensitiveKey(String key) {
        String k = key.toLowerCase(Locale.ROOT);
        return k.contains("password") || k.contains("pass")
                || k.contains("pin") || k.contains("cvv")
                || k.contains("passport") || k.contains("snils") || k.contains("inn")
                || k.contains("phone") || k.contains("email")
                || k.contains("token") || k.contains("secret")
                || k.contains("pan") || k.contains("card") || k.contains("cardnumber")
                || k.contains("balance") || k.contains("amount") || k.contains("limit")
                || k.contains("iban") || k.contains("bic") || k.contains("account")
                || k.contains("reward") || k.contains("bonus") || k.contains("points")
                || k.contains("transaction") || k.contains("redemption")
                || k.contains("programid") || k.contains("catalogid")
                || k.contains("authorizationcode");
    }

    private boolean looksSensitiveValue(JsonNode v) {
        if (v == null || v.isNull()) return false;
        if (v.isNumber()) {
            long n = v.asLong();
            // 11‑значные телефоны или 16‑значные "карты" считаем подозрительными
            int digits = String.valueOf(Math.abs(n)).length();
            return digits == 11 || digits == 16;
        }
        if (v.isTextual()) {
            String s = v.asText();
            String ls = s.toLowerCase(Locale.ROOT);
            if (s.matches("\\d{16}")) return true; // PAN‑подобный
            if (s.matches("\\+?\\d{11}")) return true; // телефон
            if (s.matches("[A-Z]{2}\\d{20,30}")) return true; // IBAN‑подобный
            if (ls.contains("@") && ls.contains(".")) return true; // email‑подобный
        }
        return false;
    }
}
