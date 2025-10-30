package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;

public class HppScanner implements SPI {
    @Override public String getCategory() { return "RateLimit"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            int max = switch (ctx.preset) { case "fast" -> 6; case "aggressive" -> 24; default -> 12; };
            int tested = 0;
            for (String p : ctx.endpoints) {
                if (tested++ >= max) break;
                String base = ctx.url(p);
                // Query duplication with stability check
                String q = "role="+enc("user")+"&role="+enc("admin")+"&hpp=1&hpp=2";
                String single = base + (base.contains("?")? "&": "?") + "role="+enc("user")+"&hpp=1";
                String duped = base + (base.contains("?")? "&": "?") + q;
                try (Response r1 = ctx.http.request("GET", single, null, null);
                     Response r2 = ctx.http.request("GET", duped, null, null)) {
                    int c1 = r1.code(), c2 = r2.code();
                    String b1 = r1.peekBody(64_000).string();
                    String b2 = r2.peekBody(64_000).string();
                    int len1 = b1.length();
                    int len2 = b2.length();
                    boolean anomaly = (c1 != c2) || Math.abs(len1-len2) > (len1*0.25 + 100);
                    // JSON‑aware diff
                    boolean jsonDiff = false;
                    try {
                        com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
                        com.fasterxml.jackson.databind.JsonNode j1 = om.readTree(b1);
                        com.fasterxml.jackson.databind.JsonNode j2 = om.readTree(b2);
                        jsonDiff = !j1.equals(j2);
                    } catch (Exception ignored) {}
                    boolean stable = false;
                    if (anomaly || jsonDiff) {
                        String dupedAlt = base + (base.contains("?")? "&": "?") + "hpp=2&hpp=1&role="+enc("admin")+"&role="+enc("user");
                        try (Response r3 = ctx.http.request("GET", dupedAlt, null, null)) {
                            int c3 = r3.code();
                            String b3 = r3.peekBody(64_000).string();
                            boolean lenStab = Math.abs(b3.length()-len2) <= (len2*0.25 + 100);
                            boolean jsonStab = false;
                            try {
                                com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
                                com.fasterxml.jackson.databind.JsonNode j2 = om.readTree(b2);
                                com.fasterxml.jackson.databind.JsonNode j3 = om.readTree(b3);
                                jsonStab = j2.equals(j3);
                            } catch (Exception ignored) {}
                            stable = (c2 == c3) || lenStab || jsonStab;
                        } catch (Exception ignored) {}
                    }
                    if ((anomaly || jsonDiff) && stable) {
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = "Medium";
                        si.endpoint = p;
                        si.method = "GET";
                        si.description = "Обнаружен HTTP Parameter Pollution (query)" + (jsonDiff? "; JSON отличается":"");
                        si.evidence = "single="+c1+", duped="+c2+", sizeDiff="+(len2-len1);
                        si.impact = "Смешивание значений параметров ведёт к обходу логики";
                        si.recommendation = "Нормализовать и валидировать параметры; запретить дубли имен";
                        si.traceRef = ctx.traceSaver.save(duped, "GET", null, r2);
                        synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                    }
                } catch (Exception ignored) {}

                // form-urlencoded: duplication in body
                try {
                    okhttp3.MediaType mt = okhttp3.MediaType.parse("application/x-www-form-urlencoded");
                    String fSingle = "mode="+enc("user")+"&flag=1";
                    String fDuped = "mode="+enc("user")+"&mode="+enc("admin")+"&flag=1&flag=2";
                    try (Response r1 = ctx.http.request("POST", base, Map.of("Content-Type","application/x-www-form-urlencoded"),
                            okhttp3.RequestBody.create(fSingle, mt));
                         Response r2 = ctx.http.request("POST", base, Map.of("Content-Type","application/x-www-form-urlencoded"),
                            okhttp3.RequestBody.create(fDuped, mt))) {
                        int c1 = r1.code(), c2 = r2.code();
                        String b1 = r1.peekBody(64_000).string();
                        String b2 = r2.peekBody(64_000).string();
                        boolean anomaly = (c1 != c2) || Math.abs(b1.length()-b2.length()) > (b1.length()*0.25 + 100);
                        if (anomaly) {
                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                            si.id = UUID.randomUUID().toString();
                            si.category = getCategory();
                            si.severity = "Medium";
                            si.endpoint = p;
                            si.method = "POST";
                            si.description = "Обнаружен HTTP Parameter Pollution (form body)";
                            si.evidence = "form single vs duped различаются";
                            si.impact = "Смешивание значений параметров ведёт к обходу логики";
                            si.recommendation = "Нормализовать и валидировать параметры; запретить дубли имен";
                            si.traceRef = ctx.traceSaver.save(base, "POST", fDuped, r2);
                            synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                        }
                    }
                } catch (Exception ignored) {}

                // duplicate headers (requires HttpClient addHeader support)
                try {
                    java.util.Map<String, java.util.List<String>> hh = new java.util.LinkedHashMap<>();
                    hh.put("X-Role", java.util.List.of("user", "admin"));
                    try (Response r = ctx.http.requestWithMultiHeaders("GET", base, hh, null)) {
                        if (r.code() < 500) {
                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                            si.id = UUID.randomUUID().toString();
                            si.category = getCategory();
                            si.severity = "Low";
                            si.endpoint = p;
                            si.method = "GET";
                            si.description = "Потенциальный HPP в заголовках (дубли X-Role)";
                            si.evidence = "X-Role: user, X-Role: admin";
                            si.impact = "Возможен обход логики при агрегации заголовков";
                            si.recommendation = "Отклонять/нормализовать дубли заголовков";
                            si.traceRef = ctx.traceSaver.save(base, "GET", null, r);
                            synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                        }
                    }
                } catch (Throwable ignored) {}
            }
        });
    }

    private String enc(String s){ return URLEncoder.encode(s, StandardCharsets.UTF_8); }
}
