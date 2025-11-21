package ru.apidefender.scanners.gost;

import com.fasterxml.jackson.databind.JsonNode;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Планировщик атак для задания (GostHackathonScanner).
 * Этап 2: строим план сценариев по OpenAPI без реальных HTTP‑запросов к тестовой площадке.
 */
public class GostHackathonScanner implements SPI {

    @Override
    public String getCategory() {
        return "GostHackathon";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                ctx.log.info("GostHackathonScanner: этап 2 — строим план атак по OpenAPI, без реальных HTTP‑запросов");

                JsonNode paths = ctx.openapi.path("paths");
                if (paths.isMissingNode() || !paths.isObject()) {
                    ctx.log.info("GostHackathonScanner: в OpenAPI отсутствует объект paths");
                    return;
                }

                int maxOps = switch (ctx.preset) {
                    case "fast" -> 0; // по умолчанию не шумим в отчёте
                    case "aggressive" -> 0;
                    default -> 0;
                };

                List<PlannedOp> planned = new ArrayList<>();
                var it = paths.fieldNames();
                while (it.hasNext()) {
                    String path = it.next();
                    JsonNode pathNode = paths.path(path);
                    for (String method : List.of("get", "post", "put", "patch", "delete")) {
                        JsonNode op = pathNode.path(method);
                        if (op.isMissingNode() || !op.isObject()) continue;
                        int score = scoreOp(path, method);
                        planned.add(new PlannedOp(path, method.toUpperCase(Locale.ROOT), score));
                    }
                }

                if (planned.isEmpty()) {
                    ctx.log.info("GostHackathonScanner: не найдено операций в OpenAPI для планирования атак");
                    return;
                }

                planned.sort((a, b) -> Integer.compare(b.score, a.score));
                if (planned.size() > maxOps) {
                    planned = planned.subList(0, maxOps);
                }

                for (PlannedOp op : planned) {
                    ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                    si.id = UUID.randomUUID().toString();
                    si.category = getCategory();
                    si.severity = "Info";
                    si.endpoint = op.path;
                    si.method = op.method;
                    si.description = "План атаки для операции " + op.method + " " + op.path +
                            " (эвристический приоритет=" + op.score + ").";
                    si.evidence = "Операция выбрана по эвристикам (BOLA/IDOR, банковская тематика, метод не GET и т.п.). " +
                            "На этом этапе реальные запросы к API не выполнялись.";
                    si.impact = "Только планирование: реальных воздействий на тестовую площадку пока нет.";
                    si.recommendation = "Использовать эту операцию в сценариях BOLA/WeakAuth/Injection/ExcessiveData на следующих этапах.";
                    si.traceRef = null;

                    synchronized (ctx.report.security) {
                        ctx.report.security.add(si);
                    }
                }

                ctx.log.info("GostHackathonScanner: сформирован план из " + planned.size() + " операций для дальнейшего тестирования");
            } catch (Exception e) {
                ctx.log.error("GostHackathonScanner: ошибка построения плана атак по OpenAPI", e);
            }
        });
    }

    private static int scoreOp(String path, String method) {
        int s = 0;
        String p = path.toLowerCase(Locale.ROOT);
        String m = method.toUpperCase(Locale.ROOT);

        if (p.contains("{") && p.contains("}")) s += 5; // BOLA/IDOR кандидаты

        if (p.contains("account")) s += 5;
        if (p.contains("card")) s += 5;
        if (p.contains("balance") || p.contains("limit")) s += 4;
        if (p.contains("payment") || p.contains("transfer") || p.contains("transaction")) s += 4;
        if (p.contains("credential") || p.contains("token")) s += 4;
        if (p.contains("deposit") || p.contains("loan") || p.contains("credit")) s += 3;

        if (!"GET".equals(m)) s += 2;

        return s;
    }

    private record PlannedOp(String path, String method, int score) {}
}
