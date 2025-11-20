package ru.apidefender.scanners.owasp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * Цепочный BOLA/IDOR-сканер: берёт реальные id из списков, пробует доступ к деталям и мутированным id.
 * Только read-only GET-запросы, без изменений состояния.
 */
public class ChainedIdorScanner implements SPI {
    @Override public String getCategory() { return "ChainedIDOR"; }

    private final ObjectMapper om = new ObjectMapper();

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            int maxLists = switch (ctx.preset) { case "aggressive" -> 8; case "fast" -> 3; default -> 5; };
            int processed = 0;
            Set<String> globalIds = new HashSet<>();
            for (String listPath : ctx.endpoints) {
                if (processed >= maxLists) break;
                JsonNode pathNode = ctx.openapi.path("paths").path(listPath).path("get");
                if (pathNode.isMissingNode()) continue; // работаем только с GET
                try (Response r = ctx.http.request("GET", ctx.url(listPath), null, null)) {
                    if (r.code() != 200) continue;
                    String ctype = Optional.ofNullable(r.header("Content-Type")).orElse("");
                    if (!ctype.contains("json")) continue;
                    String body = r.peekBody(1_000_000).string();
                    JsonNode json;
                    try { json = om.readTree(body); } catch (Exception ignored) { continue; }
                    List<String> ids = extractIds(json);
                    ids.removeIf(String::isBlank);
                    globalIds.addAll(ids);
                    if (ids.isEmpty()) continue;
                    processed++;
                    List<String> detailPaths = matchingDetailPaths(listPath, ctx.openapi.path("paths"));
                    for (String dPath : detailPaths) {
                        String placeholder = extractPlaceholder(dPath);
                        if (placeholder == null) continue;
                        for (String id : ids) {
                            String realUrl = ctx.url(dPath.replace("{"+placeholder+"}", id));
                            try (Response d = ctx.http.request("GET", realUrl, null, null)) {
                                if (d.code() != 200) continue;
                                String dBody = d.peekBody(200_000).string();
                                for (String mutated : mutations(id)) {
                                    if (mutated.equals(id)) continue;
                                    String mutUrl = ctx.url(dPath.replace("{"+placeholder+"}", mutated));
                                    try (Response mut = ctx.http.request("GET", mutUrl, null, null)) {
                                        if (mut.code() == 200) {
                                            String mBody = mut.peekBody(200_000).string();
                                            // если тела заметно отличаются — возможный IDOR
                                            if (!similar(dBody, mBody)) {
                                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                                si.id = UUID.randomUUID().toString();
                                                si.category = getCategory();
                                                si.severity = "High";
                                                si.endpoint = dPath;
                                                si.method = "GET";
                                                si.description = "Получен доступ к чужому ресурсу с другим id (вероятный IDOR)";
                                                si.evidence = "origId=" + id + " (200), mutatedId=" + mutated + " (200)";
                                                si.impact = "Неавторизованный доступ к данным других субъектов";
                                                si.recommendation = "Внедрить проверку принадлежности ресурса и применять ABAC/RBAC на уровне id";
                                                si.traceRef = ctx.traceSaver.save(mutUrl, "GET", null, mut);
                                                synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                                                // достаточно одного флага на пару id
                                                break;
                                            }
                                        }
                                    } catch (Exception ignored) {}
                                }
                            }
                        }
                    }
                } catch (Exception ignored) {}
            }

            // дополнительный brute: используем глобальный пул id и соседние значения
            for (String p : ctx.endpoints) {
                String dPath = p;
                String placeholder = extractPlaceholder(dPath);
                if (placeholder == null) continue;
                JsonNode node = ctx.openapi.path("paths").path(dPath).path("get");
                if (node.isMissingNode()) continue;
                for (String id : new ArrayList<>(globalIds)) {
                    for (String mutated : neighborMutations(id)) {
                        if (mutated.equals(id)) continue;
                        String mutUrl = ctx.url(dPath.replace("{"+placeholder+"}", mutated));
                        try (Response mut = ctx.http.request("GET", mutUrl, null, null)) {
                            if (mut.code() == 200) {
                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                si.id = UUID.randomUUID().toString();
                                si.category = getCategory();
                                si.severity = "Medium";
                                si.endpoint = dPath;
                                si.method = "GET";
                                si.description = "Получен доступ к ресурсу по соседнему id без проверки";
                                si.evidence = "mutatedId=" + mutated + " => 200";
                                si.impact = "Возможный BOLA/IDOR на соседних идентификаторах";
                                si.recommendation = "Проверять принадлежность ресурса и использовать непрогнозируемые идентификаторы";
                                si.traceRef = ctx.traceSaver.save(mutUrl, "GET", null, mut);
                                synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                                break;
                            }
                        } catch (Exception ignored) {}
                    }
                }
            }
        });
    }

    private List<String> extractIds(JsonNode json) {
        List<String> ids = new ArrayList<>();
        if (json.isArray()) {
            for (JsonNode item : json) {
                findIdsInObject(item, ids);
                if (!ids.isEmpty()) break;
            }
        } else if (json.isObject()) {
            findIdsInObject(json, ids);
        }
        return ids;
    }

    private void findIdsInObject(JsonNode obj, List<String> out) {
        if (!obj.isObject()) return;
        Iterator<String> names = obj.fieldNames();
        while (names.hasNext()) {
            String f = names.next();
            if (f.equalsIgnoreCase("id") || f.toLowerCase().endsWith("id") || f.toLowerCase().endsWith("_id")) {
                JsonNode v = obj.get(f);
                if (v.isTextual() || v.isIntegralNumber()) {
                    String s = v.asText();
                    if (!s.isBlank()) out.add(s);
                }
            }
        }
    }

    private List<String> matchingDetailPaths(String listPath, JsonNode pathsNode) {
        List<String> res = new ArrayList<>();
        String baseSegment = lastSegment(listPath);
        Iterator<String> it = pathsNode.fieldNames();
        while (it.hasNext()) {
            String p = it.next();
            if (!p.contains("{") || !p.contains("}")) continue;
            if (p.startsWith(listPath)) {
                res.add(p);
                continue;
            }
            String seg = lastSegment(p.replaceAll("\\{.*?\\}", ""));
            if (baseSegment.equals(seg)) res.add(p);
        }
        return res;
    }

    private String lastSegment(String path) {
        if (path == null || path.isEmpty()) return "";
        String[] parts = path.split("/");
        for (int i = parts.length - 1; i >=0; i--) {
            if (!parts[i].isBlank()) return parts[i];
        }
        return "";
    }

    private String extractPlaceholder(String path) {
        int a = path.indexOf('{');
        int b = path.indexOf('}');
        if (a >=0 && b>a) return path.substring(a+1, b);
        return null;
    }

    private String mutateId(String id) {
        try {
            long val = Long.parseLong(id.replaceAll("[^0-9]", ""));
            return Long.toString(val + 1);
        } catch (Exception e) {
            return id + "-test";
        }
    }

    private List<String> neighborMutations(String id) {
        List<String> res = new ArrayList<>();
        try {
            long val = Long.parseLong(id.replaceAll("[^0-9]", ""));
            res.add(Long.toString(val + 1));
            if (val > 0) res.add(Long.toString(val - 1));
            res.add(Long.toString(val + 10));
        } catch (Exception e) {
            res.add(id + "-1");
            res.add(id + "-test");
        }
        return res;
    }

    private List<String> mutations(String id) {
        List<String> res = new ArrayList<>();
        res.add(mutateId(id));
        res.addAll(neighborMutations(id));
        return res;
    }

    private boolean similar(String a, String b) {
        if (a == null || b == null) return false;
        int lenA = a.length(), lenB = b.length();
        int diff = Math.abs(lenA - lenB);
        if (diff > (lenA * 0.3 + 200)) return false;
        return a.substring(0, Math.min(200, lenA)).equals(b.substring(0, Math.min(200, lenB)));
    }
}
