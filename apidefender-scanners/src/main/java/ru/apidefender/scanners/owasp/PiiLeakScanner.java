package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Best-effort поиск утечек PII и чувствительных данных в ответах:
 * email/phone/card/идентификаторы/балансы/баллы и т.п.
 * Работает по GET‑эндпоинтам, опираясь на эвристики.
 */
public class PiiLeakScanner implements SPI {
    @Override
    public String getCategory() {
        return "PIILeak";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            int max = switch (ctx.preset) {
                case "fast" -> 10;
                case "aggressive" -> 100;
                default -> 40;
            };
            int tested = 0;
            for (String p : ctx.endpoints) {
                if (tested >= max) break;
                if (!ctx.openapi.path("paths").path(p).has("get")) continue;
                tested++;
                String url = ctx.url(p);
                try (Response r = ctx.http.request("GET", url, null, null)) {
                    String body = r.peekBody(1_000_000).string();
                    int status = r.code();
                    if (status < 200 || status >= 300) continue; // анализируем только успешные ответы
                    List<String> hits = detectPii(body);
                    if (!hits.isEmpty()) {
                        ctx.log.info("PIILeak: potential sensitive data at " + p + " hits=" + hits);
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = "High";
                        si.endpoint = p;
                        si.method = "GET";
                        si.description = "Обнаружена потенциальная утечка PII/чувствительных данных в ответе.";
                        si.evidence = String.join(", ", hits);
                        si.impact = "Возможна компрометация персональных/финансовых данных пользователя.";
                        si.recommendation = "Минимизировать объём возвращаемых данных, маскировать чувствительные поля и пересмотреть контракт API.";
                        si.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                        synchronized (ctx.report.security) {
                            ctx.report.security.add(si);
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        });
    }

    private List<String> detectPii(String body) {
        List<String> hits = new ArrayList<>();
        if (body == null || body.isEmpty()) return hits;
        try {
            String normalized = body.trim();
            String lowered = normalized.toLowerCase(Locale.ROOT);

            // Игнорируем тривиальные технические ответы вида "Not Found"
            if ("not found".equals(lowered) || "\"not found\"".equals(lowered)) {
                return hits;
            }

            // Базовые типы PII
            if (body.matches("(?is).*\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b.*")) hits.add("email");
            if (body.matches("(?s).*(?:\\+?[0-9][0-9\\-()\\s]{7,}[0-9]).*")) hits.add("phone");
            if (containsCardNumber(body)) hits.add("card");

            // Ключевые слова, связанные с документами/идентификаторами
            if (lowered.matches("(?s).*(passport|ssn|snils|inn|ogrn|driving\\s*licence|driver's|passport|паспорт|снилс|инн|огрн|email).*$")) {
                hits.add("pii-keyword");
            }

            // Доменные/финансовые данные: балансы, лимиты, вознаграждения и т.п.
            if (lowered.matches("(?s).*(balance|availablebalance|reward|rewards|rewardtype|points|bonus|bonuses|limit|credit|loan|accountid|externalaccountid|баланс|счет|счёт|баллы|лимит|кредит|депозит|займ|заём).*")) {
                hits.add("business-data");
            }

            // Похожие на имена строки
            if (body.matches("(?is).*\\b([A-Z][a-z]+\\s+[A-Z][a-z]+\\s+[A-Z][a-z]+)\\b.*")) hits.add("full-name-like");
            if (body.matches("(?ius).*\\b([А-ЯЁ][а-яё]+\\s+[А-ЯЁ][а-яё]+(?:\\s+[А-ЯЁ][а-яё]+)?)\\b.*")) hits.add("cyrillic-name-like");

            // Общая эвристика "человекоподобного" текста:
            // достаточно длинный текст, состоящий из букв и пробелов, не похожий на короткую ошибку.
            if (!normalized.isEmpty()) {
                int letters = 0;
                int spaces = 0;
                for (char c : normalized.toCharArray()) {
                    if (Character.isLetter(c)) letters++;
                    else if (c == ' ') spaces++;
                }
                if (letters >= 30 && spaces >= 3) {
                    hits.add("human-like-text");
                }
            }
        } catch (Exception ignored) {
        }
        return hits;
    }

    private boolean containsCardNumber(String body) {
        // Поиск 13-19 цифр подряд с валидацией по Luhn
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("(\\d{13,19})")
                .matcher(body.replaceAll("[^0-9]", ""));
        while (m.find()) {
            if (luhnCheck(m.group(1))) return true;
        }
        return false;
    }

    private boolean luhnCheck(String digits) {
        int sum = 0;
        boolean alt = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int n = digits.charAt(i) - '0';
            if (alt) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alt = !alt;
        }
        return sum % 10 == 0;
    }
}

