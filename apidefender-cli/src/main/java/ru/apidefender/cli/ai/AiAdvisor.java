package ru.apidefender.cli.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import ru.apidefender.core.http.Masking;
import ru.apidefender.core.log.JsonlLogger;
import ru.apidefender.core.report.ReportModel;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AiAdvisor {
    private static final MediaType JSON = MediaType.parse("application/json");
    private final OkHttpClient client;
    private final String apiKey;
    private final String model;
    private final boolean maskSecrets;
    private final JsonlLogger log;
    private final ObjectMapper mapper = new ObjectMapper();

    public AiAdvisor(String apiKey, String model, Duration timeout, boolean maskSecrets, JsonlLogger log) {
        this.apiKey = apiKey;
        this.model = model;
        this.maskSecrets = maskSecrets;
        this.log = log;
        this.client = new OkHttpClient.Builder()
                .callTimeout(timeout)
                .build();
    }

    public void enrich(List<ReportModel.SecurityIssue> issues) {
        if (issues == null || issues.isEmpty()) return;
        try {
            Map<String, AiResult> results = new HashMap<>();
            int chunkSize = 10;
            for (int i = 0; i < issues.size(); i += chunkSize) {
                List<ReportModel.SecurityIssue> sub = issues.subList(i, Math.min(i + chunkSize, issues.size()));
                try {
                    Map<String, AiResult> r = askBatch(sub);
                    results.putAll(r);
                } catch (Exception e) {
                    log.error("AI chunk failed for items "+i+".."+(Math.min(i+chunkSize, issues.size())-1), e);
                }
            }
            int processed = 0;
            for (ReportModel.SecurityIssue si : issues) {
                AiResult r = results.get(si.id);
                if (r != null) {
                    si.aiSeverity = r.severity;
                    si.aiRecommendation = r.recommendation;
                    si.aiModel = model;
                    processed++;
                }
            }
            log.info("AI enrichment completed: "+processed+" of "+issues.size()+" issues updated");
        } catch (Exception e) {
            log.error("AI enrichment failed", e);
        }
    }

    private Map<String, AiResult> askBatch(List<ReportModel.SecurityIssue> issues) throws Exception {
        ObjectNode root = mapper.createObjectNode();
        root.put("model", model);
        root.put("temperature", 0.1);
        root.put("max_tokens", 1500);
        ArrayNode messages = mapper.createArrayNode();
        messages.addObject()
                .put("role", "system")
                .put("content", "Ты эксперт по безопасности API. Дай краткие рекомендации на русском языке.");

        ArrayNode input = mapper.createArrayNode();
        for (ReportModel.SecurityIssue si : issues) {
            ObjectNode payload = mapper.createObjectNode();
            payload.put("id", nullToEmpty(si.id));
            payload.put("category", nullToEmpty(si.category));
            payload.put("scannerSeverity", nullToEmpty(si.severity));
            payload.put("endpoint", nullToEmpty(si.endpoint));
            payload.put("method", nullToEmpty(si.method));
            payload.put("description", mask(nullToEmpty(si.description)));
            payload.put("evidence", mask(nullToEmpty(si.evidence)));
            payload.put("impact", mask(nullToEmpty(si.impact)));
            input.add(payload);
        }

        String prompt = """
Верни строго JSON-массив без пояснений. Для каждого элемента входного списка создай объект вида:
{"id":"<id из входа>","severity_0_10":<число 0..10>,"recommendation_ru":"лаконичная новая рекомендация на русском, не повторяй текст входных данных"}
Важно: только JSON-массив, без текста до/после него.

Список уязвимостей:
""" + mapper.writerWithDefaultPrettyPrinter().writeValueAsString(input);

        messages.addObject()
                .put("role", "user")
                .put("content", prompt);
        root.set("messages", messages);

        Request req = new Request.Builder()
                .url("https://openrouter.ai/api/v1/chat/completions")
                .header("Authorization", "Bearer " + apiKey)
                .header("HTTP-Referer", "https://github.com/") // optional but recommended by OpenRouter
                .header("X-Title", "API Defender CLI")
                .post(RequestBody.create(root.toString(), JSON))
                .build();

        try (Response resp = client.newCall(req).execute()) {
            String body = resp.body() != null ? resp.body().string() : "";
            if (!resp.isSuccessful()) {
                String snippet = body != null && body.length() > 500 ? body.substring(0, 500) + "..." : body;
                log.error("AI request failed: HTTP " + resp.code() + ", body=" + snippet, null);
                return Map.of();
            }
            JsonNode node = mapper.readTree(body);
            JsonNode msg = node.path("choices").path(0).path("message").path("content");
            if (msg.isMissingNode()) {
                log.error("AI response missing content", null);
                return Map.of();
            }
            String content = msg.asText();
            try {
                JsonNode parsed = mapper.readTree(content);
                Map<String, AiResult> out = new HashMap<>();
                if (parsed.isArray()) {
                    for (JsonNode it : parsed) {
                        String id = it.path("id").asText(null);
                        if (id == null) continue;
                        Double severity = it.path("severity_0_10").isNumber()
                                ? it.get("severity_0_10").asDouble()
                                : extractNumber(it.path("severity_0_10").asText());
                        String rec = it.path("recommendation_ru").asText(null);
                        if (rec == null) rec = it.path("recommendation").asText(null);
                        if (severity == null && rec == null) continue;
                        out.put(id, new AiResult(severity, rec));
                    }
                }
                return out;
            } catch (Exception ignored) {
                // not JSON - try to extract best-effort number and text
                Double sev = extractNumber(content);
                return sev == null ? Map.of() : Map.of("bulk", new AiResult(sev, content.trim()));
            }
        }
    }

    private Double extractNumber(String s) {
        try {
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("([0-9]+(\\.[0-9]+)?)").matcher(s);
            if (m.find()) return Double.parseDouble(m.group(1));
        } catch (Exception ignored) {}
        return null;
    }

    private String mask(String s) {
        if (!maskSecrets) return s;
        return Masking.maskSecrets(s);
    }

    private static String nullToEmpty(String s) { return s == null? "": s; }

    private record AiResult(Double severity, String recommendation) {}
}
