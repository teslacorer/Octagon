package ru.apidefender.scanners.gost;

import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * GostContractScanner: поднимает найденные рассинхроны контракта (contract.mismatches)
 * в отдельные SecurityIssue с низкой/средней важностью.
 *
 * Это соответствует идее из prompt.md: ошибки/расхождения в OpenAPI‑контракте
 * тоже являются проблемой безопасности (OWASP API9: Improper Assets Management).
 */
public class GostContractScanner implements SPI {
    @Override
    public String getCategory() {
        return "GostContract";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                if (ctx.report == null || ctx.report.contract == null || ctx.report.contract.mismatches == null) {
                    return;
                }
                java.util.Set<String> seen = new java.util.HashSet<>();
                for (ReportModel.ContractMismatch mm : ctx.report.contract.mismatches) {
                    if (mm == null) continue;
                    String key = (mm.endpoint != null ? mm.endpoint : "") + "|" + (mm.method != null ? mm.method : "");
                    if (!seen.add(key)) continue;
                    ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                    si.id = UUID.randomUUID().toString();
                    si.category = getCategory();
                    si.endpoint = mm.endpoint;
                    si.method = mm.method;
                    si.description = "Обнаружено расхождение реализации и OpenAPI‑контракта: " + safe(mm.issue);
                    si.evidence = safe(mm.evidence);
                    si.impact = "Расхождение спецификации и реализации усложняет защиту API и может скрывать реальные уязвимости (OWASP API9: Improper Assets Management).";
                    si.recommendation = "Синхронизировать OpenAPI‑контракт с фактическим поведением сервиса и убедиться, что все пути/коды ответов корректно описаны.";
                    // Грубая оценка важности: 404 по описанному эндпоинту считаем Medium, остальное Low.
                    String sev = "Low";
                    if (mm.evidence != null && mm.evidence.contains("response.status=404")) {
                        sev = "Medium";
                    }
                    si.severity = sev;
                    si.traceRef = mm.traceRef;
                    synchronized (ctx.report.security) {
                        ctx.report.security.add(si);
                    }
                }
            } catch (Exception ignored) {
            }
        });
    }

    private String safe(String s) {
        return s == null ? "" : s;
    }
}
