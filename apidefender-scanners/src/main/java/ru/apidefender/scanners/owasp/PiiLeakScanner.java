package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Best-effort поиск PII в ответах (email/phone/card/паспортные ключевые слова).
 * Фокус на GET эндпоинтах, чтобы не вносить побочные эффекты.
 */
public class PiiLeakScanner implements SPI {
    @Override public String getCategory() { return "PIILeak"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            int max = switch (ctx.preset) { case "fast" -> 10; case "aggressive" -> 100; default -> 40; };
            int tested = 0;
            for (String p : ctx.endpoints) {
                if (tested >= max) break;
                if (!ctx.openapi.path("paths").path(p).has("get")) continue;
                tested++;
                String url = ctx.url(p);
                try (Response r = ctx.http.request("GET", url, null, null)) {
                    String body = r.peekBody(1_000_000).string();
                    int status = r.code();
                    if (status < 200 || status >= 300) continue; // только успешные
                    List<String> hits = detectPii(body);
                    if (!hits.isEmpty()) {
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = "High";
                        si.endpoint = p;
                        si.method = "GET";
                        si.description = "Найдены потенциальные PII-данные в ответе";
                        si.evidence = String.join(", ", hits);
                        si.impact = "Утечка персональных данных";
                        si.recommendation = "Фильтровать/маскировать чувствительные поля; возвращать только необходимые данные";
                        si.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                        synchronized (ctx.report.security) { ctx.report.security.add(si); }
                    }
                } catch (Exception ignored) {}
            }
        });
    }

    private List<String> detectPii(String body) {
        List<String> hits = new ArrayList<>();
        if (body == null || body.isEmpty()) return hits;
        try {
            if (body.matches("(?is).*\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b.*")) hits.add("email");
            if (body.matches("(?s).*(?:\\+?[0-9][0-9\\-()\\s]{7,}[0-9]).*")) hits.add("phone");
            if (containsCardNumber(body)) hits.add("card");
            String lowered = body.toLowerCase();
            if (lowered.matches("(?s).*(passport|ssn|snils|inn|ogrn|driving\\s*licence|driver's|passport|паспорт|снилс|инн|огрн|телефон|почта|емейл|email).*$")) hits.add("pii-keyword");
            if (body.matches("(?is).*\\b([A-Z][a-z]+\\s+[A-Z][a-z]+\\s+[A-Z][a-z]+)\\b.*")) hits.add("full-name-like");
            if (body.matches("(?ius).*\\b([А-ЯЁ][а-яё]+\\s+[А-ЯЁ][а-яё]+(?:\\s+[А-ЯЁ][а-яё]+)?)\\b.*")) hits.add("cyrillic-name-like");
        } catch (Exception ignored) {}
        return hits;
    }

    private boolean containsCardNumber(String body) {
        // ищем 13-19 цифр подряд и валидируем luhn
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(\\d{13,19})").matcher(body.replaceAll("[^0-9]", ""));
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
