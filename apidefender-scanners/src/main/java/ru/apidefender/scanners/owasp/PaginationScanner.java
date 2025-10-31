package ru.apidefender.scanners.owasp;

import okhttp3.Response;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.scanners.SPI;

import java.util.*;
import java.util.concurrent.CompletableFuture;

public class PaginationScanner implements SPI {
    @Override
    public String getCategory() {
        return "RateLimit";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            int max = switch (ctx.preset) {
                case "fast" -> 8;
                case "aggressive" -> 30;
                default -> 16;
            };
            int tested = 0;
            List<String> hints = List.of("list", "items", "transactions", "accounts", "events", "logs", "orders",
                    "payments");
            for (String p : ctx.endpoints) {
                if (tested >= max)
                    break;
                boolean candidate = false;
                String low = p.toLowerCase();
                for (String h : hints)
                    if (low.contains(h)) {
                        candidate = true;
                        break;
                    }
                if (!candidate)
                    continue;
                tested++;
                String base = ctx.url(p);
                String l50 = base + (base.contains("?") ? "&" : "?") + "limit=50&page=1";
                String l500 = base + (base.contains("?") ? "&" : "?") + "limit=500&page=1";
                String l5000 = base + (base.contains("?") ? "&" : "?") + "limit=5000&page=1&size=5000";
                long t50 = 0, t500 = 0, t5000 = 0;
                int c50 = 0, c500 = 0, c5000 = 0;
                try (Response r1 = ctx.http.request("GET", l50, null, null)) {
                    t50 = r1.receivedResponseAtMillis() - r1.sentRequestAtMillis();
                    c50 = r1.code();
                } catch (Exception ignored) {
                }
                try (Response r2 = ctx.http.request("GET", l500, null, null)) {
                    t500 = r2.receivedResponseAtMillis() - r2.sentRequestAtMillis();
                    c500 = r2.code();
                } catch (Exception ignored) {
                }
                try (Response r3 = ctx.http.request("GET", l5000, null, null)) {
                    t5000 = r3.receivedResponseAtMillis() - r3.sentRequestAtMillis();
                    c5000 = r3.code();
                    boolean slow = t5000 > Math.max(1500, Math.max(t50, t500) * 5);
                    boolean err = c5000 >= 500 || c5000 == 429;
                    if (slow || err) {
                        ReportModel.SecurityIssue si = new ReportModel.SecurityIssue();
                        si.id = UUID.randomUUID().toString();
                        si.category = getCategory();
                        si.severity = err ? "High" : "Medium";
                        si.endpoint = p;
                        si.method = "GET";
                        si.description = err ? "Деградация/ошибки на больших выборках (429/5xx)"
                                : "Замедление при больших лимитах: limit/page";
                        si.evidence = "t50=" + t50 + "ms, t500=" + t500 + "ms, t5000=" + t5000 + "ms, code5000="
                                + c5000;
                        si.impact = "Риск DoS/перегрузки и утечка ресурсов на больших лимитах";
                        si.recommendation = "Ограничить max limit/size, внедрить защиту/страничную пагинацию";
                        si.traceRef = ctx.traceSaver.save(l5000, "GET", null, r3);
                        synchronized (ctx.report.security) {
                            ctx.report.security.add(si);
                        }
                    }
                } catch (Exception ignored) {
                }
            }
        });
    }
}
