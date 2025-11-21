package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Сканер банковской поверхности: ищет типичные эндпоинты банковских/платёжных API,
 * которые не описаны в OpenAPI, но доступны по сети.
 */
public class BankSurfaceScanner implements SPI {
    @Override
    public String getCategory() {
        return "BankSurface";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            List<String> wordlist = buildWordlist();

            // исключаем пути, уже описанные в OpenAPI
            wordlist.removeIf(p -> ctx.openapi.path("paths").has(p));

            int max = switch (ctx.preset) {
                case "fast" -> 20;
                case "aggressive" -> 120;
                default -> 60;
            };
            int tested = 0;
            for (String p : wordlist) {
                if (tested >= max) break;
                tested++;
                String url = ctx.url(p);
                try (Response r = ctx.http.request("GET", url, null, null)) {
                    int code = r.code();
                    // считаем эндпоинт интересным, если он существует (2xx) или требует auth (401/403)
                    if ((code >= 200 && code < 300) || code == 401 || code == 403) {
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = classifySeverity(p, code);
                        si.endpoint = p;
                        si.method = "GET";
                        si.description = "Обнаружен банковский/платёжный эндпоинт вне спецификации OpenAPI.";
                        si.evidence = "GET " + p + " => " + code;
                        si.impact = "Поверхность атаки включает дополнительные банковские операции и данные, не описанные в контракте.";
                        si.recommendation = "Ограничить доступ (auth/ACL), пересмотреть необходимость публичной экспозиции и при необходимости явно описать эндпоинт в OpenAPI.";
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

    private List<String> buildWordlist() {
        List<String> list = new ArrayList<>();

        // Базовые сущности счетов и карт
        list.add("/accounts");
        list.add("/accounts/balances");
        list.add("/accounts/transactions");
        list.add("/accounts/{accountId}");
        list.add("/accounts/{accountId}/balance");
        list.add("/accounts/{accountId}/transactions");
        list.add("/accounts/statement");

        list.add("/cards");
        list.add("/cards/{cardId}");
        list.add("/cards/{cardId}/limits");
        list.add("/cards/{cardId}/pin");
        list.add("/cards/{cardId}/statement");
        list.add("/cards/{cardId}/requisites");

        // Платежи и переводы
        list.add("/payments");
        list.add("/payments/start");
        list.add("/payments/confirm");
        list.add("/payments/schedule");
        list.add("/payments/templates");
        list.add("/payments/domestic");
        list.add("/payments/international");
        list.add("/payments/sepa");
        list.add("/payments/instant");
        list.add("/payments/{paymentId}");

        list.add("/transfers");
        list.add("/transfers/internal");
        list.add("/transfers/external");
        list.add("/transfers/p2p");
        list.add("/transfers/p2p/card");
        list.add("/transfers/p2p/phone");

        // Кредиты и депозиты
        list.add("/loans");
        list.add("/loans/offers");
        list.add("/loans/applications");
        list.add("/loans/{loanId}");
        list.add("/loans/{loanId}/schedule");

        list.add("/deposits");
        list.add("/deposits/{depositId}");
        list.add("/deposits/{depositId}/schedule");

        // Лимиты, тарифы, FX
        list.add("/limits");
        list.add("/limits/card");
        list.add("/limits/account");
        list.add("/tariffs");
        list.add("/fees");
        list.add("/fx");
        list.add("/fx/rates");

        // Клиент и KYC
        list.add("/customer");
        list.add("/customer/profile");
        list.add("/customer/kyc");
        list.add("/customer/contacts");
        list.add("/customer/risk");

        // Согласия, офферы, лояльность
        list.add("/consents");
        list.add("/consents/{consentId}");
        list.add("/offers");
        list.add("/offers/{offerId}");
        list.add("/rewards");
        list.add("/rewards/balance");
        list.add("/loyalty");
        list.add("/loyalty/points");

        // Токены и авторизация
        list.add("/auth/token");
        list.add("/auth/refresh");
        list.add("/auth/logout");
        list.add("/sessions");
        list.add("/sessions/active");

        // Общие банковские каталоги
        list.add("/catalog/products");
        list.add("/catalog/operations");
        list.add("/catalog/fees");
        list.add("/catalog/countries");
        list.add("/catalog/currencies");

        // Open Banking / PSD2 style
        list.add("/v1/accounts");
        list.add("/v1/accounts/{accountId}/balances");
        list.add("/v1/accounts/{accountId}/transactions");
        list.add("/v1/payments");
        list.add("/v1/funds-confirmation");
        list.add("/v1/consents");

        // Варианты с /api и версионированием (v1/v2/open-banking)
        List<String> prefixes = List.of("/api", "/api/v1", "/api/v2", "/open-banking/v1", "/open-banking/v2");
        List<String> base = new ArrayList<>(list);
        for (String prefix : prefixes) {
            for (String p : base) {
                if (p.startsWith("/")) {
                    list.add(prefix + p);
                }
            }
        }

        return list;
    }

    private String classifySeverity(String path, int code) {
        String p = path.toLowerCase();
        boolean highRisk =
                p.contains("pin") ||
                p.contains("cvv") ||
                p.contains("limits") ||
                p.contains("loans") ||
                p.contains("deposits") ||
                p.contains("payments") ||
                p.contains("transfers");

        if (highRisk && code >= 200 && code < 300) {
            return "High";
        }
        return "Medium";
    }
}

