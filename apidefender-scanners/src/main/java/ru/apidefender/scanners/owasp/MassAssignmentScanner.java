package ru.apidefender.scanners.owasp;

import okhttp3.MediaType;
import okhttp3.RequestBody;
import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class MassAssignmentScanner implements SPI {
    @Override public String getCategory() { return "MassAssignment"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            for (String p : ctx.endpoints) {
                var methods = ctx.openapi.path("paths").path(p);
                if (!methods.has("post") && !methods.has("put") && !methods.has("patch")) continue;
                String url = ctx.url(p);
                Map<String,Object> body = new LinkedHashMap<>();
                body.put("username", "test");
                body.put("isAdmin", true);
                body.put("role", "admin");
                body.put("balance", 1_000_000);
                String json = toJson(body);
                try (Response r = ctx.http.request("POST", url, Map.of("Content-Type","application/json"), RequestBody.create(json, MediaType.parse("application/json")))) {
                    String rb = r.peekBody(200_000).string();
                    if (rb.contains("isAdmin") || rb.contains("role") || rb.contains("balance")) {
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = "High";
                        si.endpoint = p;
                        si.method = "POST";
                        si.description = "Подозрение на mass assignment: сервер принял/отразил чувствительные поля";
                        si.evidence = rb.length()>300? rb.substring(0,300): rb;
                        si.impact = "Повышение привилегий/модификация критичных атрибутов";
                        si.recommendation = "Явное белое‑списочное биндинг полей";
                        si.traceRef = ctx.traceSaver.save(url, "POST", json, r);
                        synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                        break;
                    }
                } catch (Exception ignored) {}
            }
        });
    }

    private String toJson(Map<String,Object> map){
        try { return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(map);} catch (Exception e){return "{}";}
    }
}
