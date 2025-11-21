package ru.apidefender.scanners.gost;

import com.fasterxml.jackson.databind.JsonNode;
import okhttp3.MediaType;
import okhttp3.RequestBody;
import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * BOLA/IDOR-сканер, заточенный под банковский API.
 * Универсально обходит OpenAPI и дополнительно реализует банковские сценарии из prompt.md.
 */
public class GostBolaScanner implements SPI {
    private static final MediaType JSON = MediaType.parse("application/json");

    @Override
    public String getCategory() {
        return "GostBOLA";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                int maxEndpoints = switch (ctx.preset) {
                    case "fast" -> 3;
                    case "aggressive" -> Math.min(ctx.idorMax, 10);
                    default -> Math.min(ctx.idorMax, 6);
                };
                int maxOps = switch (ctx.preset) {
                    case "fast" -> 40;
                    case "aggressive" -> 200;
                    default -> 100;
                };

                int opsUsed = 0;

                // Специальные банковские сценарии (credentials/cvv/tokens/status/close/pin + rewards/balance/redemption)
                opsUsed += runBankSpecificScenarios(ctx, maxOps);
                if (opsUsed >= maxOps) return;

                // Универсальный обход OpenAPI по path-ID/query-ID
                List<String> candidates = new ArrayList<>();
                ctx.openapi.path("paths").fieldNames().forEachRemaining(p -> {
                    if (p.contains("{") && looksInterestingPath(p)) candidates.add(p);
                });

                int epCount = 0;
                for (String path : candidates) {
                    if (epCount++ >= maxEndpoints) break;
                    if (opsUsed >= maxOps) break;

                    String method = chooseMethod(ctx, path);
                    if (method == null) continue;

                    opsUsed += tryPathIdor(ctx, path, method, maxOps - opsUsed);
                    if (opsUsed >= maxOps) break;

                    opsUsed += tryQueryIdor(ctx, path, method, maxOps - opsUsed);
                    if (opsUsed >= maxOps) break;
                }
            } catch (Exception ignored) {
            }
        });
    }

    /**
     * Банковские сценарии BOLA/IDOR из prompt.md для основного API.
     */
    private int runBankSpecificScenarios(ScanContext ctx, int budget) {
        if (budget <= 0) return 0;
        int used = 0;

        // credentials/cvv/tokens/status/close/pin по publicId и набору client-ID заголовков
        List<String> paths = List.of(
                "/credentials/{publicId}",
                "/cvv/{publicId}",
                "/tokens/{publicId}",
                "/status/{publicId}",
                "/close/{publicId}",
                "/pin/{publicId}"
        );

        String[] publicIds = pickIdPair(ctx, "publicid", "123", "456");
        String selfId = publicIds[0];
        String otherId = publicIds[1];
        String clientSelf = "client-self";
        String clientOther = "client-other";

        for (String template : paths) {
            if (used >= budget) break;
            var node = ctx.openapi.path("paths").path(template);
            if (node.isMissingNode() || !node.isObject()) continue;
            String method = chooseMethod(ctx, template);
            if (method == null) continue;

            String pSelf = template.replace("{publicId}", selfId);
            String pOther = template.replace("{publicId}", otherId);
            String urlSelf = ctx.url(pSelf);
            String urlOther = ctx.url(pOther);

            try {
                // Happy Path: selfId + client-ID заголовки (X-Mdm-Id/X-MDM-ID/X-UNC/X-TB-ID/x-client-channel/X-PARTNER-ID)
                Map<String, String> hSelf = headersForClient(clientSelf);
                try (Response rSelf = ctx.trackedRequest(method, urlSelf, hSelf, null)) {
                    used++;
                    int cSelf = rSelf.code();
                    if (cSelf < 200 || cSelf >= 300) {
                        if (used >= budget) break;
                        continue;
                    }
                    String bSelf = safeBody(rSelf);

                    // BOLA по publicId: другой publicId, тот же набор client-ID заголовков
                    if (used >= budget) break;
                    try (Response rOtherId = ctx.trackedRequest(method, urlOther, hSelf, null)) {
                        used++;
                        int cOther = rOtherId.code();
                        if (cOther >= 200 && cOther < 300) {
                            String bOther = safeBody(rOtherId);
                            if (looksDifferent(bSelf, bOther)) {
                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                si.id = UUID.randomUUID().toString();
                                si.category = getCategory();
                                si.severity = "High";
                                si.endpoint = template;
                                si.method = method;
                                si.description = "Обнаружена возможная BOLA/IDOR по publicId: можно читать/менять чувствительные данные (credentials/CVV/token) по чужому publicId.";
                                si.evidence = "selfId=" + selfId + ", otherId=" + otherId + ", status=" + cSelf + "/" + cOther;
                                si.impact = "Злоумышленник может получить данные или статусы карт/токенов другого клиента, зная его publicId.";
                                si.recommendation = "На сервере жёстко связывать publicId с client-ID (X-Mdm-Id/X-MDM-ID/X-UNC/X-TB-ID/x-client-channel/X-PARTNER-ID) и блокировать доступ к чужим publicId (BOLA_PATH_ID).";
                                si.traceRef = ctx.traceSaver.save(urlOther, method, null, rOtherId);
                                synchronized (ctx.report.security) {
                                    ctx.report.security.add(si);
                                }
                            }
                        }
                    }

                    if (used >= budget) break;
                    // BOLA по client-ID: тот же publicId, другой набор client-ID заголовков
                    Map<String, String> hOther = headersForClient(clientOther);
                    try (Response rOtherMdm = ctx.trackedRequest(method, urlSelf, hOther, null)) {
                        used++;
                        int cOtherMdm = rOtherMdm.code();
                        if (cOtherMdm >= 200 && cOtherMdm < 300) {
                            String bOtherMdm = safeBody(rOtherMdm);
                            if (looksDifferent(bSelf, bOtherMdm)) {
                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                si.id = UUID.randomUUID().toString();
                                si.category = getCategory();
                                si.severity = "High";
                                si.endpoint = template;
                                si.method = method;
                                si.description = "Обнаружена возможная BOLA/IDOR по client-ID заголовку: данные по publicId доступны при другом client-ID (X-Mdm-Id/X-MDM-ID/X-UNC/X-TB-ID/x-client-channel/X-PARTNER-ID).";
                                si.evidence = "clientId_self=" + clientSelf + " vs clientId_other=" + clientOther + ", status=" + cSelf + "/" + cOtherMdm;
                                si.impact = "Злоумышленник может подменить client-ID заголовки и читать/менять данные другого клиента (BOLA_CLIENT_ID).";
                                si.recommendation = "Проверять связку всех client-ID заголовков и publicId на сервере и блокировать запросы с чужими значениями.";
                                si.traceRef = ctx.traceSaver.save(urlSelf, method, null, rOtherMdm);
                                synchronized (ctx.report.security) {
                                    ctx.report.security.add(si);
                                }
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }

        // rewards/balance: BOLA по externalAccountID + X-MDM-ID
        if (used >= budget) return used;
        String rewardsPath = "/cards/accounts/external/{externalAccountID}/rewards/balance";
        var rewardsNode = ctx.openapi.path("paths").path(rewardsPath);
        if (!rewardsNode.isMissingNode() && rewardsNode.isObject() && used < budget) {
            String method = chooseMethod(ctx, rewardsPath);
            if (method != null) {
                String[] accIds = pickIdPair(ctx, "externalaccountid", "acc-self", "acc-other");
                String accSelf = accIds[0];
                String accOther = accIds[1];
                String pSelf = rewardsPath.replace("{externalAccountID}", accSelf);
                String pOther = rewardsPath.replace("{externalAccountID}", accOther);
                String urlSelf = ctx.url(pSelf);
                String urlOther = ctx.url(pOther);

                try {
                    Map<String, String> hSelf = headersForClient(clientSelf);
                    hSelf.put("X-MDM-ID", clientSelf);
                    try (Response rSelf = ctx.trackedRequest(method, urlSelf, hSelf, null)) {
                        used++;
                        int cSelf = rSelf.code();
                        if (cSelf >= 200 && cSelf < 300) {
                            String bSelf = safeBody(rSelf);
                            // Всегда сохраняем хотя бы один happy‑path трейс для balance
                            try { ctx.traceSaver.save(urlSelf, method, null, rSelf); } catch (Exception ignored) {}
                            if (used < budget) {
                                try (Response rOther = ctx.trackedRequest(method, urlOther, hSelf, null)) {
                                    used++;
                                    int cOther = rOther.code();
                                    if (cOther >= 200 && cOther < 300) {
                                        String bOther = safeBody(rOther);
                                        if (looksDifferent(bSelf, bOther)) {
                                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                            si.id = UUID.randomUUID().toString();
                                            si.category = getCategory();
                                            si.severity = "High";
                                            si.endpoint = rewardsPath;
                                            si.method = method;
                                            si.description = "Обнаружена возможная BOLA/IDOR по externalAccountID: можно читать rewards balance для чужого счёта.";
                                            si.evidence = "self=" + accSelf + ", other=" + accOther + ", status=" + cSelf + "/" + cOther;
                                            si.impact = "Злоумышленник может получить информацию о балансе/кэшбэке другого клиента по номеру счёта.";
                                            si.recommendation = "Проверять принадлежность externalAccountID к текущему клиенту по X-MDM-ID и другим client-ID заголовкам (BOLA_PATH_ID).";
                                            si.traceRef = ctx.traceSaver.save(urlOther, method, null, rOther);
                                            synchronized (ctx.report.security) {
                                                ctx.report.security.add(si);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }

        // rewards/redemption: BOLA по externalAccountID + X-MDM-ID (пример из задания)
        if (used >= budget) return used;
        String redPath = "/cards/accounts/external/{externalAccountID}/rewards/redemption";
        var redNode = ctx.openapi.path("paths").path(redPath);
        if (!redNode.isMissingNode() && redNode.isObject() && used < budget) {
            String method = chooseMethod(ctx, redPath);
            if (method != null) {
                String[] accIds = pickIdPair(ctx, "externalaccountid", "acc-self", "acc-other");
                String accSelf = accIds[0];
                String accOther = accIds[1];
                String pSelf = redPath.replace("{externalAccountID}", accSelf);
                String pOther = redPath.replace("{externalAccountID}", accOther);
                String urlSelf = ctx.url(pSelf);
                String urlOther = ctx.url(pOther);

                String body = """
{
  "data": {
    "redemptionReferenceNumber": "1c4717c4-d4a5-e3f3-4a71-b868908763ff",
    "redemptionAmount": 50,
    "valuePerPoint": 0.01,
    "programId": "A7DV56B",
    "catalogId": "C9AP78DS9K",
    "redemptionInfo": {
      "authorizationCode": "5R20BK11W6",
      "transactionID": 584922,
      "transactionDesc": "Онлайн-заказ для погашения кредита"
    }
  }
}
""";

                try {
                    Map<String, String> hSelf = headersForClient(clientSelf);
                    hSelf.put("X-MDM-ID", clientSelf);
                    hSelf.put("Content-Type", "application/json");
                    RequestBody rb = RequestBody.create(body, JSON);
                    try (Response rSelf = ctx.trackedRequest(method, urlSelf, hSelf, rb)) {
                        used++;
                        int cSelf = rSelf.code();
                        if (cSelf >= 200 && cSelf < 300) {
                            String bSelf = safeBody(rSelf);
                            // Всегда сохраняем happy‑path трейс для redemption,
                            // даже если BOLA‑различия не будет
                            try { ctx.traceSaver.save(urlSelf, method, body, rSelf); } catch (Exception ignored) {}
                            if (used < budget) {
                                try (Response rOther = ctx.trackedRequest(method, urlOther, hSelf, rb)) {
                                    used++;
                                    int cOther = rOther.code();
                                    if (cOther >= 200 && cOther < 300) {
                                        String bOther = safeBody(rOther);
                                        if (looksDifferent(bSelf, bOther)) {
                                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                            si.id = UUID.randomUUID().toString();
                                            si.category = getCategory();
                                            si.severity = "High";
                                            si.endpoint = redPath;
                                            si.method = method;
                                            si.description = "Обнаружена возможная BOLA/IDOR по externalAccountID: redemption/погашение может выполняться по чужому счёту.";
                                            si.evidence = "self=" + accSelf + ", other=" + accOther + ", status=" + cSelf + "/" + cOther;
                                            si.impact = "Злоумышленник может инициировать операции погашения/списания по счёту другого клиента, используя его externalAccountID.";
                                            si.recommendation = "Связывать externalAccountID с X-MDM-ID и другими client-ID заголовками на сервере и блокировать redemption по чужим счетам (BOLA_PATH_ID для платёжных операций).";
                                            si.traceRef = ctx.traceSaver.save(urlOther, method, body, rOther);
                                            synchronized (ctx.report.security) {
                                                ctx.report.security.add(si);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }

        // /leads: BOLA/IDOR ���? leadId � query-��ࠬ���
        if (used >= budget) return used;
        String leadsPath = "/leads";
        var leadsNode = ctx.openapi.path("paths").path(leadsPath);
        if (!leadsNode.isMissingNode() && leadsNode.isObject() && used < budget) {
            String method = chooseMethod(ctx, leadsPath);
            if (method != null) {
                String[] leadIds = pickIdPair(ctx, "leadid", "456789", "456790");
                String leadSelf = leadIds[0];
                String leadOther = leadIds[1];
                String base = ctx.url(leadsPath);
                String urlSelf = appendQuery(base, "leadId", leadSelf);
                String urlOther = appendQuery(base, "leadId", leadOther);

                try {
                    Map<String, String> headers = new HashMap<>();
                    headers.put("X-Global-Transaction-ID", "apidefender-" + UUID.randomUUID());
                    try (Response rSelf = ctx.trackedRequest(method, urlSelf, headers, null)) {
                        used++;
                        int cSelf = rSelf.code();
                        if (cSelf >= 200 && cSelf < 300) {
                            String bSelf = safeBody(rSelf);
                            try { ctx.traceSaver.save(urlSelf, method, null, rSelf); } catch (Exception ignored) {}
                            if (used < budget) {
                                try (Response rOther = ctx.trackedRequest(method, urlOther, headers, null)) {
                                    used++;
                                    int cOther = rOther.code();
                                    if (cOther >= 200 && cOther < 300) {
                                        String bOther = safeBody(rOther);
                                        if (looksDifferent(bSelf, bOther)) {
                                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                            si.id = UUID.randomUUID().toString();
                                            si.category = getCategory();
                                            si.severity = "High";
                                            si.endpoint = leadsPath;
                                            si.method = method;
                                            si.description = "�?�+�?���?�?���?�� �?�?���?�?��?���? BOLA/IDOR ���? leadId: �?�?��?�? �ؐ�'���'�? ������ �� ������ ����� �����.";
                                            si.evidence = "selfLeadId=" + leadSelf + ", otherLeadId=" + leadOther + ", status=" + cSelf + "/" + cOther;
                                            si.impact = "�-�>�?�?�?�<�?�>��?�?��� �?�?���' ����� �⢥� �� ����� ����� �� �����䨪��� ����.";
                                            si.recommendation = "�?�?�?�?��?�?�'�? ���?��?���?�>���?�?�?�'�? �� �?��?�?�?�?�� leadId �� �'���?�%��?�? ���?���?��� �����.";
                                            si.traceRef = ctx.traceSaver.save(urlOther, method, null, rOther);
                                            synchronized (ctx.report.security) {
                                                ctx.report.security.add(si);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }

        // /customer-leads/{customerLeadId}: BOLA/IDOR ���? customerLeadId (path)
        if (used >= budget) return used;
        String custLeadPath = "/customer-leads/{customerLeadId}";
        var custNode = ctx.openapi.path("paths").path(custLeadPath);
        if (!custNode.isMissingNode() && custNode.isObject() && used < budget) {
            String method = chooseMethod(ctx, custLeadPath);
            if (method != null) {
                String[] ids = pickIdPair(ctx, "customerleadid", "95791e79-0f2d-47de-a5e0-df034b28574a", "95791e79-0f2d-47de-a5e0-df034b28574b");
                String idSelf = ids[0];
                String idOther = ids[1];
                String pSelf = custLeadPath.replace("{customerLeadId}", idSelf);
                String pOther = custLeadPath.replace("{customerLeadId}", idOther);
                String urlSelf = ctx.url(pSelf);
                String urlOther = ctx.url(pOther);

                try {
                    try (Response rSelf = ctx.trackedRequest(method, urlSelf, null, null)) {
                        used++;
                        int cSelf = rSelf.code();
                        if (cSelf >= 200 && cSelf < 300) {
                            String bSelf = safeBody(rSelf);
                            try { ctx.traceSaver.save(urlSelf, method, null, rSelf); } catch (Exception ignored) {}
                            if (used < budget) {
                                try (Response rOther = ctx.trackedRequest(method, urlOther, null, null)) {
                                    used++;
                                    int cOther = rOther.code();
                                    if (cOther >= 200 && cOther < 300) {
                                        String bOther = safeBody(rOther);
                                        if (looksDifferent(bSelf, bOther)) {
                                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                            si.id = UUID.randomUUID().toString();
                                            si.category = getCategory();
                                            si.severity = "High";
                                            si.endpoint = custLeadPath;
                                            si.method = method;
                                            si.description = "�?�+�?���?�?���?�� �?�?���?�?��?���? BOLA/IDOR ���? customerLeadId: əࠧ�� ����� �⢥� �� ���������樨 �� ������ customerLeadId.";
                                            si.evidence = "self=" + idSelf + ", other=" + idOther + ", status=" + cSelf + "/" + cOther;
                                            si.impact = "�-�>�?�?�?�<�?�>��?�?��� �?�?���' ����� �⢥� �� ���������樨 �� ������ �����䨪��� ����.";
                                            si.recommendation = "�?�?�?�?��?�?�'�? ���?��?���?�>���?�?�?�'�? �� �?��?�?�?�?�� customerLeadId �� �'���?�%��?�? ���?���?��� �����.";
                                            si.traceRef = ctx.traceSaver.save(urlOther, method, null, rOther);
                                            synchronized (ctx.report.security) {
                                                ctx.report.security.add(si);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        }

        return used;
    }

    /**
     * Собираем набор client-ID заголовков, перечисленных в prompt.md.
     */
    private Map<String, String> headersForClient(String clientId) {
        Map<String, String> h = new HashMap<>();
        h.put("X-Mdm-Id", clientId);
        h.put("X-MDM-ID", clientId);
        h.put("X-UNC", clientId);
        h.put("X-TB-ID", clientId);
        h.put("x-client-channel", "online");
        h.put("X-PARTNER-ID", "partner-" + clientId);
        return h;
    }

    private boolean looksInterestingPath(String p) {
        String s = p.toLowerCase(Locale.ROOT);
        return s.contains("account")
                || s.contains("card")
                || s.contains("payment")
                || s.contains("transfer")
                || s.contains("credential")
                || s.contains("token")
                || s.contains("deposit")
                || s.contains("loan")
                || s.contains("credit")
                || s.contains("balance")
                || s.contains("limit")
                || s.contains("application")
                || s.contains("offer")
                || s.contains("consent")
                || s.contains("customer-leads")
                || s.contains("product-application");
    }

    private String chooseMethod(ScanContext ctx, String path) {
        var node = ctx.openapi.path("paths").path(path);
        for (String m : List.of("get", "post", "put", "patch", "delete")) {
            if (node.has(m)) return m.toUpperCase(Locale.ROOT);
        }
        return null;
    }

    private int tryPathIdor(ScanContext ctx, String path, String method, int budget) {
        if (budget <= 0 || !path.contains("{")) return 0;
        List<String> ids = List.of("1", "2", "42", "1001", "1002");
        String p1 = path.replaceAll("\\{[^/]+}", ids.get(0));
        String p2 = path.replaceAll("\\{[^/]+}", ids.get(1));
        String url1 = ctx.url(p1);
        String url2 = ctx.url(p2);

        int used = 0;
        try (Response r1 = ctx.http.request(method, url1, null, null)) {
            used++;
            if (used >= budget) return used;
            try (Response r2 = ctx.http.request(method, url2, null, null)) {
                used++;
                int c1 = r1.code();
                int c2 = r2.code();
                if (c1 >= 200 && c1 < 300 && c2 >= 200 && c2 < 300) {
                    String b1 = safeBody(r1);
                    String b2 = safeBody(r2);
                    if (!b1.isEmpty() && !b2.isEmpty()) {
                        boolean diff = Math.abs(b1.length() - b2.length()) > (b1.length() * 0.2 + 50);
                        if (diff) {
                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                            si.id = UUID.randomUUID().toString();
                            si.category = getCategory();
                            si.severity = "High";
                            si.endpoint = path;
                            si.method = method;
                            si.description = "Обнаружена возможная BOLA/IDOR по path-параметру: разные данные для разных ID при одинаковом токене.";
                            si.evidence = method + " " + p1 + " => " + c1 + " (" + b1.length() + " байт), " +
                                    method + " " + p2 + " => " + c2 + " (" + b2.length() + " байт)";
                            si.impact = "Возможна горизонтальная эскалация прав: доступ к чужим объектам по угадываемым идентификаторам.";
                            si.recommendation = "Проверять принадлежность ресурса аутентифицированному пользователю (object-level authorization, BOLA).";
                            si.traceRef = ctx.traceSaver.save(url2, method, null, r2);
                            synchronized (ctx.report.security) {
                                ctx.report.security.add(si);
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return used;
    }

    private int tryQueryIdor(ScanContext ctx, String path, String method, int budget) {
        if (budget <= 0) return 0;
        String base = ctx.url(path);
        List<String> keys = List.of("id", "accountId", "clientId", "userId");
        List<String> ids = List.of("1", "2", "42", "1001", "1002");

        int used = 0;
        for (String key : keys) {
            if (used >= budget) break;
            String url1 = appendQuery(base, key, ids.get(0));
            String url2 = appendQuery(base, key, ids.get(1));
            try (Response r1 = ctx.http.request(method, url1, null, null)) {
                used++;
                if (used >= budget) break;
                try (Response r2 = ctx.http.request(method, url2, null, null)) {
                    used++;
                    int c1 = r1.code();
                    int c2 = r2.code();
                    if (c1 >= 200 && c1 < 300 && c2 >= 200 && c2 < 300) {
                        String b1 = safeBody(r1);
                        String b2 = safeBody(r2);
                        if (!b1.isEmpty() && !b2.isEmpty()) {
                            boolean diff = Math.abs(b1.length() - b2.length()) > (b1.length() * 0.2 + 50);
                            if (diff) {
                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                si.id = UUID.randomUUID().toString();
                                si.category = getCategory();
                                si.severity = "Medium";
                                si.endpoint = path;
                                si.method = method;
                                si.description = "Обнаружена возможная IDOR по query-параметру '" + key + "'.";
                                si.evidence = method + " " + url1 + " => " + c1 + " (" + b1.length() + " байт), " +
                                        method + " " + url2 + " => " + c2 + " (" + b2.length() + " байт)";
                                si.impact = "Возможен доступ к данным другого клиента при подборе идентификатора в query-параметре.";
                                si.recommendation = "Проверять авторизацию на уровне объекта для ресурсов, идентифицируемых через '" + key + "'.";
                                si.traceRef = ctx.traceSaver.save(url2, method, null, r2);
                                synchronized (ctx.report.security) {
                                    ctx.report.security.add(si);
                                }
                            }
                        }
                    }
                }
            } catch (Exception ignored) {
            }
        }
        return used;
    }

    private String appendQuery(String base, String key, String value) {
        String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8);
        if (base.contains("?")) {
            return base + "&" + key + "=" + encoded;
        }
        return base + "?" + key + "=" + encoded;
    }

    private String safeBody(Response r) {
        try {
            return r.peekBody(80_000).string();
        } catch (Exception ignored) {
            return "";
        }
    }

    private boolean looksDifferent(String a, String b) {
        if (a == null || b == null) return false;
        if (a.isEmpty() || b.isEmpty()) return false;
        if (a.equals(b)) return false;
        return Math.abs(a.length() - b.length()) > (a.length() * 0.2 + 50);
    }

    private String[] pickIdPair(ScanContext ctx, String keyHint, String defSelf, String defOther) {
        String hint = keyHint.toLowerCase(Locale.ROOT);
        // 1) Пытаемся использовать реально обнаруженные ID
        String foundKey = null;
        if (ctx.discoveredIds != null && !ctx.discoveredIds.isEmpty()) {
            for (String k : ctx.discoveredIds.keySet()) {
                String lk = k.toLowerCase(Locale.ROOT);
                if (lk.equals(hint) || lk.endsWith(hint) || lk.contains(hint)) {
                    foundKey = k;
                    break;
                }
            }
        }
        if (foundKey != null) {
            java.util.List<String> values = ctx.discoveredIds.get(foundKey);
            if (values != null && !values.isEmpty()) {
                String self = values.get(0);
                String other = values.size() > 1 ? values.get(1) : mutateId(self);
                return new String[] { self, other };
            }
        }
        // 2) Пытаемся взять example из OpenAPI (components.parameters / inline parameters)
        String example = findExampleForKey(ctx, hint);
        if (example != null && !example.isBlank()) {
            String self = example;
            String other = mutateId(example);
            return new String[] { self, other };
        }
        // 3) Фолбэк на дефолтные значения
        return new String[] { defSelf, defOther };
    }

    private String findExampleForKey(ScanContext ctx, String hint) {
        try {
            // components.parameters
            var comps = ctx.openapi.path("components").path("parameters");
            if (comps.isObject()) {
                java.util.Iterator<String> it = comps.fieldNames();
                while (it.hasNext()) {
                    String pname = it.next();
                    JsonNode param = comps.path(pname);
                    String name = param.path("name").asText("");
                    String lname = name.toLowerCase(Locale.ROOT);
                    if (!lname.contains(hint)) continue;
                    JsonNode ex = param.get("example");
                    if (ex != null && !ex.isNull()) return ex.asText();
                }
            }
            // inline parameters under paths
            JsonNode paths = ctx.openapi.path("paths");
            if (paths.isObject()) {
                java.util.Iterator<String> pit = paths.fieldNames();
                while (pit.hasNext()) {
                    String p = pit.next();
                    JsonNode pathNode = paths.path(p);
                    for (String m : List.of("get","post","put","patch","delete")) {
                        JsonNode op = pathNode.path(m);
                        if (!op.isObject()) continue;
                        JsonNode params = op.path("parameters");
                        if (!params.isArray()) continue;
                        for (JsonNode param : params) {
                            String name = param.path("name").asText("");
                            String lname = name.toLowerCase(Locale.ROOT);
                            if (!lname.contains(hint)) continue;
                            JsonNode ex = param.get("example");
                            if (ex != null && !ex.isNull()) return ex.asText();
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private String mutateId(String id) {
        if (id == null || id.isBlank()) return id;
        char[] chars = id.toCharArray();
        for (int i = chars.length - 1; i >= 0; i--) {
            char c = chars[i];
            if (Character.isDigit(c)) {
                chars[i] = (c == '9') ? '0' : (char)(c + 1);
                return new String(chars);
            }
            if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                chars[i] = (c == 'f' || c == 'F') ? 'a' : (char)(Character.toLowerCase(c) + 1);
                return new String(chars);
            }
        }
        // если ничего не поменяли – просто добавим суффикс
        return id + "1";
    }
}
