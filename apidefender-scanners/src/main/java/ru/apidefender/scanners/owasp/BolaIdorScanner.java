package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.*;
import java.util.concurrent.CompletableFuture;

public class BolaIdorScanner implements SPI {
    @Override public String getCategory() { return "IDOR"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                // Лимиты, зависящие от пресета: сдерживаем длительность IDOR
                int harvestCap = switch (ctx.preset) { case "fast" -> 8; case "aggressive" -> 40; default -> 20; };
                int poolCap    = switch (ctx.preset) { case "fast" -> 4; case "aggressive" -> 20; default -> 10; };
                int xsubEpCap  = switch (ctx.preset) { case "fast" -> 8; case "aggressive" -> 30; default -> 16; };
                int xsubIdsCap = switch (ctx.preset) { case "fast" -> 4; case "aggressive" -> 16; default -> 8; };
                // Общий бюджет HTTP-попыток внутри IDOR (жёсткий стоп)
                int opsCap     = switch (ctx.preset) { case "fast" -> 120; case "aggressive" -> 600; default -> 300; };
                final int opsLimit = opsCap;
                final int[] opsUsed = new int[]{0};
                java.util.function.BooleanSupplier hasBudget = () -> opsUsed[0] < opsLimit;
                java.util.function.Consumer<Integer> spend = (n) -> opsUsed[0] += n;

                // Кандидаты с path-параметрами
                List<String> candidates = new ArrayList<>();
                ctx.openapi.path("paths").fieldNames().forEachRemaining(p -> { if (p.contains("{")) candidates.add(p); });
                // Сбор ID из открытых GET ответов
                List<String> harvested = harvestIds(ctx, harvestCap);
                int max = ctx.idorMax;
                int count = 0;
                for (String p : candidates) {
                    if (count++ >= max) break;
                    if (!hasBudget.getAsBoolean()) break;
                    // Пул значений ограничиваем
                    List<String> pool = new ArrayList<>(harvested);
                    pool.addAll(List.of("1","2","3","42","99","999999","1234567890","00000001",
                            java.util.UUID.randomUUID().toString(), java.util.UUID.randomUUID().toString()));
                    if (pool.size() > poolCap) pool = pool.subList(0, poolCap);
                    // Попытка «свой/чужой»: сравнить два разных ID
                    if (!pool.isEmpty()) {
                        String id1 = pool.get(0);
                        String id2 = pool.size() > 1 ? pool.get(1) : pool.get(0);
                        String c1 = p.replaceAll("\\{[^/]+}", id1);
                        String c2 = p.replaceAll("\\{[^/]+}", id2);
                        if (hasBudget.getAsBoolean()) try (Response r1 = ctx.http.request("GET", ctx.url(c1), null, null)) {
                            spend.accept(1);
                            if (!hasBudget.getAsBoolean()) {
                                try { r1.close(); } catch (Exception ignored) {}
                            }
                            if (hasBudget.getAsBoolean()) try (Response r2 = ctx.http.request("GET", ctx.url(c2), null, null)) {
                                spend.accept(1);
                            int k1 = r1.code(); int k2 = r2.code();
                            String b1 = r1.peekBody(80_000).string();
                            String b2 = r2.peekBody(80_000).string();
                            boolean ok = (k1>=200 && k1<300) && (k2>=200 && k2<300);
                            boolean diff = Math.abs(b1.length()-b2.length()) > (b1.length()*0.2 + 50);
                            if (ok && diff) {
                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                si.id = UUID.randomUUID().toString();
                                // Отдельно классифицируем BOLA на пользовательских ресурсах
                                si.category = (p.toLowerCase().contains("/user") || p.toLowerCase().contains("users/")) ? "BOLA" : getCategory();
                                si.severity = "High";
                                si.endpoint = p;
                                si.method = "GET";
                                si.description = "Подтверждённый IDOR/BOLA: различный контент для разных ID";
                                si.evidence = "GET "+c1+" => "+k1+", GET "+c2+" => "+k2;
                                si.impact = "Несанкционированный доступ к чужим данным";
                                si.recommendation = "Проверка владения ресурсом и авторизация на уровне ресурса";
                                si.traceRef = ctx.traceSaver.save(ctx.url(c2), "GET", null, r2);
                                synchronized (ctx.report.security){ ctx.report.security.add(si); }
                                continue; // к следующему кандидату
                            }
                            } catch (Exception ignored) {}
                        } catch (Exception ignored) {}
                    }
                    // Если «свой/чужой» не сработал — пробуем по одному ID из пула
                    for (String val : pool) {
                        if (!hasBudget.getAsBoolean()) break;
                        String crafted = p.replaceAll("\\{[^/]+}", val);
                        String url = ctx.url(crafted);
                        try (Response r = ctx.http.request("GET", url, null, null)) {
                            spend.accept(1);
                            int code = r.code();
                            if (code >= 200 && code < 300) {
                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                si.id = UUID.randomUUID().toString();
                                si.category = (p.toLowerCase().contains("/user") || p.toLowerCase().contains("users/")) ? "BOLA" : getCategory();
                                si.severity = "High";
                                si.endpoint = p;
                                si.method = "GET";
                                si.description = "Подтверждённый IDOR/BOLA: доступ к ресурсу с произвольным ID";
                                si.evidence = "GET "+crafted+" => "+code;
                                si.impact = "Несанкционированный доступ к чужим данным";
                                si.recommendation = "Проверка владения ресурсом и авторизация на уровне ресурса";
                                si.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                                synchronized (ctx.report.security){ ctx.report.security.add(si); }
                                break;
                            }
                        } catch (Exception ignored) {}
                    }
                }

                // Кросс-подстановка в query: userId/accountId/ownerId
                List<String> idKeys = List.of("userId","accountId","ownerId","customerId");
                int epCount = 0;
                for (String path : ctx.endpoints) {
                    if (epCount++ >= xsubEpCap) break;
                    if (!hasBudget.getAsBoolean()) break;
                    String base = ctx.url(path);
                    for (String key : idKeys) {
                        int usedForKey = 0;
                        for (String id : harvested) {
                            if (usedForKey++ >= xsubIdsCap) break;
                            if (!hasBudget.getAsBoolean()) break;
                            String url = base + (base.contains("?")? "&": "?") + key + "=" + java.net.URLEncoder.encode(id, java.nio.charset.StandardCharsets.UTF_8);
                            try (Response r = ctx.http.request("GET", url, null, null)) {
                                spend.accept(1);
                                if (r.code() >= 200 && r.code() < 300) {
                                    ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                    si.id = UUID.randomUUID().toString();
                                    si.category = getCategory();
                                    si.severity = "Medium";
                                    si.endpoint = path;
                                    si.method = "GET";
                                    si.description = "IDOR через query-параметр: "+key;
                                    si.evidence = "GET "+url+" => "+r.code();
                                    si.impact = "Доступ к данным по произвольному идентификатору";
                                    si.recommendation = "Валидировать владение ресурсом, игнорировать внешние ID в query";
                                    si.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                                    synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                                    break;
                                }
                            } catch (Exception ignored) {}
                        }
                    }
                }
            } catch (Exception ignored) {}
        });
    }

    private List<String> harvestIds(ScanContext ctx, int budget){
        List<String> ids = new ArrayList<>();
        try {
            java.util.Iterator<String> it = ctx.openapi.path("paths").fieldNames();
            int used = 0;
            while (it.hasNext() && used < budget) {
                String p = it.next();
                if (p.contains("{")) continue;
                String url = ctx.url(p);
                try (Response r = ctx.http.request("GET", url, null, null)) {
                    String body = r.peekBody(120_000).string();
                    ids.addAll(extractIdsFromJson(body));
                    used++;
                } catch (Exception ignored) {}
            }
        } catch (Exception ignored) {}
        return ids.stream().filter(s -> s!=null && !s.isBlank()).distinct().limit(50).toList();
    }

    private List<String> extractIdsFromJson(String body){
        List<String> out = new ArrayList<>();
        try {
            com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.JsonNode node = om.readTree(body);
            walk(node, out);
        } catch (Exception ignored) {}
        return out;
    }

    private void walk(com.fasterxml.jackson.databind.JsonNode n, List<String> out){
        if (n == null) return;
        if (n.isObject()) {
            java.util.Iterator<String> fn = n.fieldNames();
            while (fn.hasNext()) {
                String k = fn.next();
                com.fasterxml.jackson.databind.JsonNode v = n.get(k);
                if (looksLikeIdKey(k) && (v.isTextual() || v.isNumber())) {
                    String s = v.asText();
                    if (looksLikeUuid(s) || s.length() <= 20) out.add(s);
                }
                walk(v, out);
            }
        } else if (n.isArray()) {
            for (com.fasterxml.jackson.databind.JsonNode e : n) walk(e, out);
        }
    }

    private boolean looksLikeIdKey(String k){
        String key = k.toLowerCase();
        return key.equals("id") || key.endsWith("id") || key.contains("userid") ||
                key.contains("accountid") || key.contains("paymentid") ||
                key.contains("productid") || key.contains("agreementid") ||
                key.contains("applicationid");
    }

    private boolean looksLikeUuid(String s){
        return s != null && s.matches("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    }
}
