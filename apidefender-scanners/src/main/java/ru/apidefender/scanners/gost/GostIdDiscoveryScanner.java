package ru.apidefender.scanners.gost;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Response;
import ru.apidefender.scanners.SPI;

import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;

/**
 * Вспомогательный сканер: проходит по части GET‑эндпоинтов и вытаскивает реальные идентификаторы
 * (externalAccountID, publicId, paymentId, applicationId, offerId, consentId, customerLeadId, productApplicationId и т.п.)
 * из JSON‑ответов. Результат сохраняется в ctx.discoveredIds и используется другими Gost‑сканерами.
 */
public class GostIdDiscoveryScanner implements SPI {
    @Override
    public String getCategory() {
        return "GostIdDiscovery";
    }

    @Override
    public CompletableFuture<Void> run(ScanContext ctx) {
        return CompletableFuture.runAsync(() -> {
            try {
                ObjectMapper mapper = new ObjectMapper();
                int maxEndpoints = switch (ctx.preset) {
                    case "fast" -> 10;
                    case "aggressive" -> 40;
                    default -> 20;
                };

                int epCount = 0;
                for (String path : ctx.endpoints) {
                    if (epCount++ >= maxEndpoints) break;
                    // интересуют в первую очередь read‑эндпоинты
                    String method = "GET";
                    String url = ctx.url(path);
                    try (Response r = ctx.trackedRequest(method, url, null, null)) {
                        int code = r.code();
                        if (code < 200 || code >= 300) continue;
                        String body = r.peekBody(80_000).string();
                        if (body == null || body.isBlank()) continue;
                        JsonNode root;
                        try {
                            root = mapper.readTree(body);
                        } catch (Exception ignored) {
                            continue;
                        }
                        collectIds(ctx, root);
                    } catch (Exception ignored) {
                    }
                }
            } catch (Exception ignored) {
            }
        });
    }

    private void collectIds(ScanContext ctx, JsonNode node) {
        if (node == null || node.isNull()) return;
        if (node.isObject()) {
            Iterator<String> it = node.fieldNames();
            while (it.hasNext()) {
                String field = it.next();
                JsonNode v = node.get(field);
                if (looksLikeIdField(field) && v != null && !v.isNull()) {
                    if (v.isTextual()) {
                        ctx.addDiscoveredId(field, v.asText());
                    } else if (v.isNumber()) {
                        ctx.addDiscoveredId(field, v.asText());
                    }
                }
                collectIds(ctx, v);
            }
        } else if (node.isArray()) {
            for (JsonNode v : node) {
                collectIds(ctx, v);
            }
        }
    }

    private boolean looksLikeIdField(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        List<String> keys = List.of(
                "externalaccountid",
                "publicid",
                "paymentid",
                "applicationid",
                "offerid",
                "consentid",
                "customerleadid",
                "productapplicationid",
                "clientid",
                "accountid",
                "id"
        );
        for (String k : keys) {
            if (n.equals(k) || n.endsWith(k) || n.contains(k)) return true;
        }
        return false;
    }
}

