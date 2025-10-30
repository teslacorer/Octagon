package ru.apidefender.scanners.owasp;

import okhttp3.MediaType;
import okhttp3.RequestBody;
import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.*;
import java.util.concurrent.CompletableFuture;

public class MethodOverrideScanner implements SPI {
    @Override public String getCategory() { return "MethodOverride"; }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            int max = switch (ctx.preset) { case "fast" -> 6; case "aggressive" -> 24; default -> 12; };
            int tested = 0;
            for (String p : ctx.endpoints) {
                if (tested++ >= max) break;
                String url = ctx.url(p);
                try (Response base = ctx.http.request("GET", url, null, null)) {
                    int baseCode = base.code();

                    // 1) X-HTTP-Method-Override
                    Map<String,String> h = new LinkedHashMap<>();
                    h.put("X-HTTP-Method-Override","DELETE");
                    try (Response over = ctx.http.request("POST", url, h, null)) { reportIfOverride(ctx, p, baseCode, over, "X-HTTP-Method-Override"); } catch (Exception ignored) {}

                    // 2) _method in query
                    String url2 = url + (url.contains("?")? "&":"?") + "_method=DELETE";
                    try (Response over2 = ctx.http.request("POST", url2, null, null)) { reportIfOverride(ctx, p, baseCode, over2, "_method=query"); } catch (Exception ignored) {}

                    // 3) X-Original-Method
                    Map<String,String> h2 = new LinkedHashMap<>();
                    h2.put("X-Original-Method","DELETE");
                    try (Response over3 = ctx.http.request("POST", url, h2, null)) { reportIfOverride(ctx, p, baseCode, over3, "X-Original-Method"); } catch (Exception ignored) {}

                    // 4) X-HTTP-Method
                    Map<String,String> h3 = new LinkedHashMap<>();
                    h3.put("X-HTTP-Method","DELETE");
                    try (Response over4 = ctx.http.request("POST", url, h3, null)) { reportIfOverride(ctx, p, baseCode, over4, "X-HTTP-Method"); } catch (Exception ignored) {}

                    // 5) X-Method-Override
                    Map<String,String> h4 = new LinkedHashMap<>();
                    h4.put("X-Method-Override","DELETE");
                    try (Response over5 = ctx.http.request("POST", url, h4, null)) { reportIfOverride(ctx, p, baseCode, over5, "X-Method-Override"); } catch (Exception ignored) {}

                    // 6) _method in form body
                    try {
                        MediaType mt = MediaType.parse("application/x-www-form-urlencoded");
                        String body = "_method=DELETE";
                        try (Response over6 = ctx.http.request("POST", url, Map.of("Content-Type","application/x-www-form-urlencoded"),
                                RequestBody.create(body, mt))) { reportIfOverride(ctx, p, baseCode, over6, "_method=form"); } catch (Exception ignored) {}
                    } catch (Exception ignored) {}
                } catch (Exception ignored) {}
            }
        });
    }

    private void reportIfOverride(ScanContext ctx, String endpoint, int baseCode, Response over, String variant){
        int oc = over.code();
        if (oc != baseCode && oc < 500) {
            ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
            si.id = UUID.randomUUID().toString();
            si.category = getCategory();
            si.severity = "Medium";
            si.endpoint = endpoint;
            si.method = "POST";
            si.description = "Небезопасный метод-override через " + variant;
            si.evidence = "GET="+baseCode+", POST+"+variant+"=DELETE => "+oc;
            si.impact = "Возможен обход контроля методов/авторизации";
            si.recommendation = "Отключить/валидировать method override и применять явный список";
            si.traceRef = ctx.traceSaver.save(over.request().url().toString(), over.request().method(), null, over);
            synchronized (ctx.report.security){ ctx.report.security.add(si);} 
        }
    }
}
