package ru.apidefender.scanners.gost;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Дополнительный сканер: анализирует уже сохранённые трассы (out/traces/*.json)
 * и ищет избыточное раскрытие данных (PII) в ответах любого метода (GET/POST/PUT).
 * Категория такая же, как у онлайн‑сканера: GostExcessiveData.
 */
public class GostTracePiiScanner implements SPI {
    @Override
    public String getCategory() {
        return "GostExcessiveData";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                ObjectMapper om = new ObjectMapper();
                String dirStr = ctx.report.meta != null ? ctx.report.meta.tracesDir : null;
                if (dirStr == null || dirStr.isBlank()) return;

                Path dir = Paths.get(dirStr);
                if (!Files.isDirectory(dir)) return;

                Files.list(dir)
                        .filter(p -> p.toString().endsWith(".json"))
                        .forEach(p -> {
                            try {
                                String raw = Files.readString(p, StandardCharsets.UTF_8);
                                JsonNode trace = om.readTree(raw);
                                int status = trace.path("status").asInt();
                                if (status < 200 || status >= 300) return;
                                String respBody = trace.path("responseBody").asText("");
                                if (respBody == null || respBody.isBlank()) return;
                                JsonNode root;
                                try {
                                    root = om.readTree(respBody);
                                } catch (Exception ignoredInner) {
                                    return;
                                }
                List<String> suspicious = new ArrayList<>();
                collectSuspiciousFields(root, "", suspicious);
                if (suspicious.isEmpty()) return;

                // dedupe: если уже есть issue для этой трассы в категории GostExcessiveData – не добавляем ещё один
                String traceFile = p.getFileName().toString();
                synchronized (ctx.report.security) {
                    for (ReportModel.SecurityIssue existing : ctx.report.security) {
                        if ("GostExcessiveData".equals(existing.category)
                                && traceFile.equals(existing.traceRef)) {
                            return;
                        }
                    }
                }

                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                si.id = UUID.randomUUID().toString();
                si.category = getCategory();
                                si.severity = "Medium";
                                si.endpoint = trace.path("url").asText("");
                                si.method = trace.path("method").asText("");
                                si.description = "Обнаружено возможное избыточное раскрытие чувствительных данных (по сохранённой трассе).";
                                si.evidence = "Подозрительные поля: " + String.join(", ", suspicious);
                                si.impact = "Может приводить к утечке PII/финансовых данных (PAN/CVV/PIN/балансы/лимиты и т.п.).";
                                si.recommendation = "Пересмотреть набор возвращаемых полей и маскировать/убирать PII из ответов внешнему клиенту.";
                                si.traceRef = traceFile;
                                synchronized (ctx.report.security) {
                                    ctx.report.security.add(si);
                                }
                            } catch (Exception ignoredFile) {
                            }
                        });
            } catch (Exception ignored) {
            }
        });
    }

    private void collectSuspiciousFields(JsonNode node, String prefix, List<String> out) {
        if (node == null) return;
        if (node.isObject()) {
            var it = node.fieldNames();
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
            int digits = String.valueOf(Math.abs(n)).length();
            return digits == 11 || digits == 16;
        }
        if (v.isTextual()) {
            String s = v.asText();
            String ls = s.toLowerCase(Locale.ROOT);
            if (s.matches("\\d{16}")) return true;           // PAN‑подобный
            if (s.matches("\\+?\\d{11}")) return true;       // телефон‑подобный
            if (s.matches("[A-Z]{2}\\d{20,30}")) return true; // IBAN‑подобный
            if (ls.contains("@") && ls.contains(".")) return true; // email‑подобный
        }
        return false;
    }
}
