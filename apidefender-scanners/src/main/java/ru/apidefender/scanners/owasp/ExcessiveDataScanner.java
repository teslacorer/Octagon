package ru.apidefender.scanners.owasp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.*;
import java.util.concurrent.CompletableFuture;

public class ExcessiveDataScanner implements SPI {
    @Override public String getCategory() { return "ExcessiveData"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            ObjectMapper mapper = new ObjectMapper();
            for (String p : ctx.endpoints) {
                String url = ctx.url(p);
                try (Response r = ctx.http.request("GET", url, null, null)) {
                    String ctype = r.header("Content-Type");
                    if (ctype != null && ctype.contains("application/json")) {
                        String body = r.peekBody(1_000_000).string();
                        JsonNode node = mapper.readTree(body);
                        // найти schema
                        JsonNode respNode = ctx.openapi.path("paths").path(p).path("get").path("responses");
                        JsonNode target = respNode.has(Integer.toString(r.code())) ? respNode.get(Integer.toString(r.code())) : respNode.get("default");
                        if (target != null) {
                            JsonNode schema = target.path("content").path("application/json").path("schema");
                            List<String> extra = new ArrayList<>();
                            findUnknown(node, schema, "$.body", extra);
                            if (!extra.isEmpty()) {
                                ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                                si.id = UUID.randomUUID().toString();
                                si.category = getCategory();
                                si.severity = "Medium";
                                si.endpoint = p;
                                si.method = "GET";
                                si.description = "Лишние поля в ответе, не описанные в схеме";
                                si.evidence = String.join(", ", extra);
                                si.impact = "Избыточная выдача данных";
                                si.recommendation = "Скрыть неописанные поля, скорректировать схему";
                                si.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                                synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                            }
                            // PII detection (best-effort)
                            List<String> piiHits = detectPii(body);
                            if (!piiHits.isEmpty()) {
                                ReportModel.SecurityIssue si2 = new ReportModel.SecurityIssue();
                                si2.id = UUID.randomUUID().toString();
                                si2.category = getCategory();
                                si2.severity = "Medium";
                                si2.endpoint = p;
                                si2.method = "GET";
                                si2.description = "Обнаружены потенциальные PII-поля в ответе";
                                si2.evidence = String.join(", ", piiHits);
                                si2.impact = "Риск утечки персональных данных";
                                si2.recommendation = "Исключить/маскировать PII в ответах, внедрить фильтрацию";
                                si2.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                                synchronized (ctx.report.security){ ctx.report.security.add(si2);} 
                            }
                        }
                    }
                } catch (Exception ignored) {}
            }
        });
    }

    private void findUnknown(JsonNode node, JsonNode schema, String path, List<String> out) {
        if (schema == null || schema.isMissingNode()) return;
        String type = schema.path("type").asText(null);
        if (type != null && type.equals("object") && node.isObject()) {
            JsonNode props = schema.path("properties");
            boolean additional = schema.path("additionalProperties").asBoolean(true);
            if (!additional && props.isObject()) {
                node.fieldNames().forEachRemaining(fn -> { if (!props.has(fn)) out.add(path+":"+fn); });
            }
            if (props.isObject()) {
                props.fieldNames().forEachRemaining(fn -> { if (node.has(fn)) findUnknown(node.get(fn), props.get(fn), path+"."+fn, out); });
            }
        } else if (type != null && type.equals("array") && node.isArray()) {
            JsonNode items = schema.path("items");
            for (int i=0;i<node.size();i++) findUnknown(node.get(i), items, path+"["+i+"]", out);
        }
    }

    private List<String> detectPii(String body) {
        List<String> hits = new ArrayList<>();
        try {
            if (body == null) return hits;
            if (body.matches("(?s).*[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}.*")) hits.add("email");
            if (body.matches("(?s).*(?:\\+?[0-9][0-9\\-()\\s]{7,}[0-9]).*")) hits.add("phone");
            if (body.matches("(?s).*(?:[0-9]{13,19}).*")) hits.add("card-like");
            if (body.toLowerCase().matches("(?s).*(passport|ssn|inn|snils).*")) hits.add("PII-keywords");
        } catch (Exception ignored) {}
        return hits;
    }
}



