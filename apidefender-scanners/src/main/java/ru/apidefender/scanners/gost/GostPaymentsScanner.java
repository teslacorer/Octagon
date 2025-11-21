package ru.apidefender.scanners.gost;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Специализированные сценарии BOLA/IDOR для платежей и заявок на продукты:
 * /payments/{paymentId}, /product-application/{productApplicationId}.
 */
public class GostPaymentsScanner implements SPI {
    @Override
    public String getCategory() {
        return "GostBOLAPayments";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                int budget = switch (ctx.preset.toLowerCase(Locale.ROOT)) {
                    case "fast" -> 20;
                    case "aggressive" -> 80;
                    default -> 40;
                };
                int used = 0;

                used += scanPaymentById(ctx, budget - used);
                if (used >= budget) return;
                used += scanProductApplicationById(ctx, budget - used);
            } catch (Exception ignored) {
            }
        });
    }

    private int scanPaymentById(ScanContext ctx, int budget) {
        if (budget <= 0) return 0;
        String path = "/payments/{paymentId}";
        var node = ctx.openapi.path("paths").path(path);
        if (node.isMissingNode() || !node.isObject()) return 0;
        String method = chooseMethod(ctx, path);
        if (method == null) return 0;

        String[] ids = pickIdPair(ctx, "paymentid", "pay-self", "pay-other");
        String idSelf = ids[0];
        String idOther = ids[1];
        String pSelf = path.replace("{paymentId}", idSelf);
        String pOther = path.replace("{paymentId}", idOther);
        String urlSelf = ctx.url(pSelf);
        String urlOther = ctx.url(pOther);

        int used = 0;
        try {
            Map<String, String> headers = Map.of("X-MDM-ID", "mdm-self");
            try (Response rSelf = ctx.trackedRequest(method, urlSelf, headers, null)) {
                used++;
                int cSelf = rSelf.code();
                if (cSelf >= 200 && cSelf < 300) {
                    String bSelf = safeBody(rSelf);
                    try { ctx.traceSaver.save(urlSelf, method, null, rSelf); } catch (Exception ignored) {}
                    if (used >= budget) return used;
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
                                si.endpoint = path;
                                si.method = method;
                                si.description = "Обнаружен возможный BOLA/IDOR по paymentId: разные данные о платеже по разным paymentId при одинаковом X-MDM-ID.";
                                si.evidence = "selfPaymentId=" + idSelf + ", otherPaymentId=" + idOther + ", status=" + cSelf + "/" + cOther;
                                si.impact = "Потенциальная утечка деталей чужого платежа (сумма, реквизиты, статусы).";
                                si.recommendation = "Реализовать object-level authorization по paymentId с привязкой к клиентскому идентификатору (X-MDM-ID).";
                                si.traceRef = ctx.traceSaver.save(urlOther, method, null, rOther);
                                synchronized (ctx.report.security) {
                                    ctx.report.security.add(si);
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return used;
    }

    private int scanProductApplicationById(ScanContext ctx, int budget) {
        if (budget <= 0) return 0;
        String path = "/product-application/{productApplicationId}";
        var node = ctx.openapi.path("paths").path(path);
        if (node.isMissingNode() || !node.isObject()) return 0;
        String method = chooseMethod(ctx, path);
        if (method == null) return 0;

        String[] ids = pickIdPair(ctx, "productapplicationid", "app-self", "app-other");
        String idSelf = ids[0];
        String idOther = ids[1];
        String pSelf = path.replace("{productApplicationId}", idSelf);
        String pOther = path.replace("{productApplicationId}", idOther);
        String urlSelf = ctx.url(pSelf);
        String urlOther = ctx.url(pOther);

        int used = 0;
        try {
            try (Response rSelf = ctx.trackedRequest(method, urlSelf, null, null)) {
                used++;
                int cSelf = rSelf.code();
                if (cSelf >= 200 && cSelf < 300) {
                    String bSelf = safeBody(rSelf);
                    try { ctx.traceSaver.save(urlSelf, method, null, rSelf); } catch (Exception ignored) {}
                    if (used >= budget) return used;
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
                                si.endpoint = path;
                                si.method = method;
                                si.description = "Обнаружен возможный BOLA/IDOR по productApplicationId: разные данные заявки по разным productApplicationId при одном и том же токене.";
                                si.evidence = "selfProductApplicationId=" + idSelf + ", otherProductApplicationId=" + idOther + ", status=" + cSelf + "/" + cOther;
                                si.impact = "Потенциальная утечка деталей чужой заявки на продукт (статусы, параметры).";
                                si.recommendation = "Реализовать object-level authorization по productApplicationId и связке с владельцем (PSU).";
                                si.traceRef = ctx.traceSaver.save(urlOther, method, null, rOther);
                                synchronized (ctx.report.security) {
                                    ctx.report.security.add(si);
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }
        return used;
    }

    private String chooseMethod(ScanContext ctx, String path) {
        var node = ctx.openapi.path("paths").path(path);
        for (String m : java.util.List.of("get", "post", "put", "patch", "delete")) {
            if (node.has(m)) return m.toUpperCase(Locale.ROOT);
        }
        return null;
    }

    private String[] pickIdPair(ScanContext ctx, String keyHint, String defSelf, String defOther) {
        String hint = keyHint.toLowerCase(Locale.ROOT);
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
                return new String[]{self, other};
            }
        }
        return new String[]{defSelf, defOther};
    }

    private String mutateId(String id) {
        if (id == null || id.isBlank()) return id;
        char[] chars = id.toCharArray();
        for (int i = chars.length - 1; i >= 0; i--) {
            char c = chars[i];
            if (Character.isDigit(c)) {
                chars[i] = (c == '9') ? '0' : (char) (c + 1);
                return new String(chars);
            }
        }
        return id + "1";
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
}

