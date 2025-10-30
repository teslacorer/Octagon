package ru.apidefender.cli.commands;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.Response;
import picocli.CommandLine;
import ru.apidefender.core.Config;
import ru.apidefender.core.http.HttpClient;
import ru.apidefender.core.log.JsonlLogger;
import ru.apidefender.core.openapi.OpenApiLoader;
import ru.apidefender.core.report.ReportModel;
import ru.apidefender.core.report.ReportWriter;
import ru.apidefender.core.risk.RiskAssessor;
import ru.apidefender.scanners.SPI;
import ru.apidefender.scanners.owasp.*;
import ru.apidefender.scanners.simple.CorsHeadersScanner;
import ru.apidefender.scanners.simple.SecurityHeadersScanner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

@CommandLine.Command(name = "scan", description = "Сканирование API: проверка контракта и OWASP")
public class ScanCommand implements Callable<Integer> {
    private static class Op { final String path; final String method; Op(String p,String m){this.path=p;this.method=m;} }

    @CommandLine.Option(names = "--openapi", description = "Путь к OpenAPI (JSON/YAML)", defaultValue = "/app/specs/openapi.json")
    Path openapi;
    @CommandLine.Option(names = "--base-url", description = "Базовый URL целевой системы")
    String baseUrl;
    @CommandLine.Option(names = "--token-file", required = true, description = "Путь к файлу с JWT")
    Path tokenFile;
    @CommandLine.Option(names = "--preset", description = "Профиль: fast|full|aggressive", defaultValue = "full")
    String preset;
    @CommandLine.Option(names = "--timeout", description = "Таймаут выполнения (например, 5m)", defaultValue = "5m")
    String timeout;
    @CommandLine.Option(names = "--concurrency", description = "Число параллельных потоков")
    Integer concurrency;
    @CommandLine.Option(names = "--report-html", description = "Путь к HTML отчёту", defaultValue = "/out/report.html")
    Path reportHtml;
    @CommandLine.Option(names = "--report-pdf", description = "Путь к PDF отчёту", defaultValue = "/out/report.pdf")
    Path reportPdf;
    @CommandLine.Option(names = "--report-json", description = "Путь к JSON отчёту", defaultValue = "/out/report.json")
    Path reportJson;
    @CommandLine.Option(names = "--save-traces", description = "Каталог для сохранения raw-трейсов", defaultValue = "/out/traces")
    Path tracesDir;
    @CommandLine.Option(names = "--log-level", description = "Уровень логирования: info|debug", defaultValue = "info")
    String logLevel;
    @CommandLine.Option(names = "--discover-undocumented", description = "Поиск неописанных эндпоинтов", defaultValue = "true")
    boolean discoverUndocumented;
    @CommandLine.Option(names = "--strict-contract", description = "Строгая проверка контракта", defaultValue = "true")
    boolean strictContract;
    @CommandLine.Option(names = "--log-file", description = "Путь к файлу логов JSONL", defaultValue = "/out/scan.log")
    Path logFile;
    @CommandLine.Option(names = "--public-path", description = "Публичный путь (можно указывать несколько)", split = ",")
    List<String> publicPaths;
    @CommandLine.Option(names = "--allow-cors-wildcard-public", description = "Разрешить CORS * для публичных путей", defaultValue = "true")
    boolean allowCorsWildcardPublic;
    @CommandLine.Option(names = "--exploit-depth", description = "Глубина эксплуатации: low|med|high")
    String exploitDepth;
    @CommandLine.Option(names = "--max-exploit-ops", description = "Ограничение попыток эксплуатации", defaultValue = "40")
    int maxExploitOps;
    @CommandLine.Option(names = "--safety-skip-delete", description = "Не выполнять DELETE при эксплуатации", defaultValue = "true")
    boolean safetySkipDelete;

    @CommandLine.Option(names = "--debug", description = "Подробные трейсы (печать полных запросов/ответов)", defaultValue = "false")
    boolean debugFlag;

    @CommandLine.Option(names = "--mask-secrets", description = "Маскировать секреты (JWT) в логах/трейсах", defaultValue = "true")
    boolean maskSecrets;

    @CommandLine.Option(names = "--telemetry-endpoint", description = "URL для отправки анонимной телеметрии")
    String telemetryEndpoint;

    @CommandLine.Option(names = "--telemetry-opt-in", description = "Разрешить отправку анонимной телеметрии", defaultValue = "false")
    boolean telemetryOptIn;

    private static JsonNode cachedSpecRoot;

    private static Duration parseDuration(String s) {
        if (s.endsWith("ms")) return Duration.ofMillis(Long.parseLong(s.substring(0, s.length()-2)));
        if (s.endsWith("s")) return Duration.ofSeconds(Long.parseLong(s.substring(0, s.length()-1)));
        if (s.endsWith("m")) return Duration.ofMinutes(Long.parseLong(s.substring(0, s.length()-1)));
        if (s.endsWith("h")) return Duration.ofHours(Long.parseLong(s.substring(0, s.length()-1)));
        return Duration.ofMinutes(5);
    }

    @Override
    public Integer call() throws Exception {
        boolean debug = Objects.equals(logLevel, "debug") || debugFlag;
        JsonlLogger log = new JsonlLogger(debug, logFile);
        Instant started = Instant.now();
        log.info("Начало сканирования: базовый URL=" + (baseUrl!=null? baseUrl: "(из OpenAPI)") + ", пресет="+preset);

        OpenApiLoader loader = new OpenApiLoader();
        OpenApiLoader.LoadedSpec spec = loader.load(openapi);
        String targetBase = baseUrl != null? baseUrl: Optional.ofNullable(spec.firstServerUrl).orElse("http://localhost:8080");
        cachedSpecRoot = spec.root;

        Config.Preset pr = switch (preset.toLowerCase()) {
            case "fast" -> Config.Preset.FAST;
            case "aggressive" -> Config.Preset.AGGRESSIVE;
            default -> Config.Preset.FULL;
        };
        Duration dur = parseDuration(timeout);
        int threads = concurrency != null? concurrency: Math.max(2, Runtime.getRuntime().availableProcessors());

        String token = Files.readString(tokenFile).trim();
        Files.createDirectories(tracesDir);

        HttpClient http = new HttpClient(dur, token, maskSecrets);
        ReportModel report = new ReportModel();
        report.meta.startedAt = started.toString();
        report.meta.preset = pr.name().toLowerCase();
        report.meta.target = targetBase;
        report.meta.openapiVersion = spec.version;
        report.meta.tracesDir = tracesDir.toString();

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<Void>> tasks = new ArrayList<>();

        List<String> endpoints = new ArrayList<>();
        if (spec.root.has("paths")) {
            spec.root.get("paths").fieldNames().forEachRemaining(endpoints::add);
        }
        List<Op> ops = new ArrayList<>();
        String[] allMethods = new String[]{"get","post","put","patch","delete","head","options","trace"};
        for (String p : endpoints) {
            JsonNode node = spec.root.path("paths").path(p);
            for (String m : allMethods) if (node.has(m)) ops.add(new Op(p, m));
        }
        // приоритизация «чувствительных» ручек
        List<String> hot = List.of("auth","user","account","payment","transfer","card","token","admin","secret");
        ops.sort((a,b)->{
            int sa = scoreOp(a.path, a.method, hot);
            int sb = scoreOp(b.path, b.method, hot);
            return Integer.compare(sb, sa);
        });

        for (Op op : ops) {
            final String p = op.path; final String m = op.method; final String methodUpper = m.toUpperCase();
            tasks.add(() -> {
                String url = (targetBase.endsWith("/")? targetBase.substring(0, targetBase.length()-1): targetBase) + (p.startsWith("/")? p: "/"+p);
                long t0 = System.nanoTime();
                try (Response r = http.request(methodUpper, url, null, null)) {
                    long dt = (System.nanoTime()-t0)/1_000_000L;
                    synchronized (report) {
                        report.telemetry.requestsTotal++;
                        report.telemetry.avgLatencyMs += dt;
                    }
                    int code = r.code();
                    JsonNode respNode = spec.root.path("paths").path(p).path(m).path("responses");
                    boolean inSpec = respNode.has(Integer.toString(code)) || respNode.has("default");
                    if (!inSpec) {
                        ReportModel.ContractMismatch cm = new ReportModel.ContractMismatch();
                        cm.endpoint = p; cm.method = methodUpper;
                        cm.issue = "Код ответа не описан в OpenAPI: "+code;
                        cm.evidence = "response.status="+code;
                        cm.traceRef = saveFullTrace(url, methodUpper, null, r);
                        synchronized (report.contract.mismatches){ report.contract.mismatches.add(cm);} 
                    } else {
                        JsonNode target = respNode.has(Integer.toString(code)) ? respNode.get(Integer.toString(code)) : respNode.get("default");
                        JsonNode content = target.path("content");
                        if (content.isMissingNode() || content.isNull() || !content.fieldNames().hasNext()) {
                            ReportModel.ContractMismatch cm = new ReportModel.ContractMismatch();
                            cm.endpoint = p; cm.method = methodUpper;
                            cm.issue = "Предупреждение: отсутствует content/schema в OpenAPI для кода " + code;
                            cm.evidence = "response.status="+code;
                            cm.traceRef = saveFullTrace(url, methodUpper, null, r);
                            synchronized (report.contract.mismatches){ report.contract.mismatches.add(cm);} 
                        } else {
                            String ctype = r.header("Content-Type");
                            boolean ctypeDescribed = false;
                            if (ctype != null) {
                                Iterator<String> it = content.fieldNames();
                                while (it.hasNext()) { if (ctype.contains(it.next())) { ctypeDescribed = true; break; } }
                            }
                            if (ctype != null && !ctypeDescribed) {
                                ReportModel.ContractMismatch cm = new ReportModel.ContractMismatch();
                                cm.endpoint = p; cm.method = methodUpper;
                                cm.issue = "Неверный Content-Type: не описан в OpenAPI: " + ctype;
                                cm.evidence = "content-type="+ctype;
                                cm.traceRef = saveFullTrace(url, methodUpper, null, r);
                                synchronized (report.contract.mismatches){ report.contract.mismatches.add(cm);} 
                            }
                            if (ctype != null && ctype.contains("application/json")) {
                                JsonNode jsonSchema = content.path("application/json").path("schema");
                                if (!jsonSchema.isMissingNode()) {
                                    try {
                                        String body = r.peekBody(5_000_000).string();
                                        ObjectMapper mapper = new ObjectMapper();
                                        JsonNode node = mapper.readTree(body);
                                        List<String> errs = new ArrayList<>();
                                        validateJson(node, jsonSchema, "$.body", errs);
                                        if (!errs.isEmpty()) {
                                            ReportModel.ContractMismatch cm = new ReportModel.ContractMismatch();
                                            cm.endpoint = p; cm.method = methodUpper;
                                            cm.issue = "Нарушение схемы ответа: " + String.join("; ", errs);
                                            cm.evidence = "content-type=application/json";
                                            cm.traceRef = saveFullTrace(url, methodUpper, null, r);
                                            synchronized (report.contract.mismatches){ report.contract.mismatches.add(cm);} 
                                        }
                                        if (code >= 400 && content.has("application/problem+json")) {
                                            List<String> perrs = new ArrayList<>();
                                            if (!node.has("title")) perrs.add("нет title");
                                            if (!node.has("status")) perrs.add("нет status");
                                            if (!perrs.isEmpty()) {
                                                ReportModel.ContractMismatch cm = new ReportModel.ContractMismatch();
                                                cm.endpoint = p; cm.method = methodUpper;
                                                cm.issue = "Неверный problem+json: " + String.join(", ", perrs);
                                                cm.evidence = "application/problem+json";
                                                cm.traceRef = saveFullTrace(url, methodUpper, null, r);
                                                synchronized (report.contract.mismatches){ report.contract.mismatches.add(cm);} 
                                            }
                                        }
                                    } catch (Exception ignored) { }
                                } else {
                                    ReportModel.ContractMismatch cm = new ReportModel.ContractMismatch();
                                    cm.endpoint = p; cm.method = methodUpper;
                                    cm.issue = "Предупреждение: отсутствует schema для application/json";
                                    cm.evidence = "content-type=application/json";
                                    cm.traceRef = saveFullTrace(url, methodUpper, null, r);
                                    synchronized (report.contract.mismatches){ report.contract.mismatches.add(cm);} 
                                }
                            }
                            JsonNode reqHeaders = target.path("headers");
                            if (reqHeaders.isObject()) {
                                Iterator<String> it = reqHeaders.fieldNames();
                                while (it.hasNext()) {
                                    String h = it.next();
                                    if (r.header(h) == null) {
                                        ReportModel.ContractMismatch cm = new ReportModel.ContractMismatch();
                                        cm.endpoint = p; cm.method = methodUpper;
                                        cm.issue = "Отсутствует обязательный заголовок ответа: "+h;
                                        cm.evidence = "headers."+h+"=<none>";
                                        cm.traceRef = saveFullTrace(url, methodUpper, null, r);
                                        synchronized (report.contract.mismatches){ report.contract.mismatches.add(cm);} 
                                    }
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    ReportModel.ContractMismatch cm = new ReportModel.ContractMismatch();
                    cm.endpoint = p; cm.method = methodUpper;
                    cm.issue = "Ошибка запроса: "+ e.getClass().getSimpleName();
                    cm.evidence = Optional.ofNullable(e.getMessage()).orElse("");
                    cm.traceRef = UUID.randomUUID().toString();
                    synchronized (report.contract.mismatches){ report.contract.mismatches.add(cm);} 
                }
                return null;
            });
        }

        if (discoverUndocumented) {
            Set<String> known = new HashSet<>();
            spec.root.path("paths").fieldNames().forEachRemaining(known::add);
            Set<String> candidates = new LinkedHashSet<>();
            // словарь общих путей
            List<String> common = List.of(
                    "/actuator", "/actuator/health", "/actuator/info", "/actuator/env", "/actuator/metrics", "/actuator/beans", "/actuator/loggers", "/actuator/mappings",
                    "/admin", "/admin/health", "/admin/info", "/internal", "/internal/status", "/internal/metrics",
                    "/status", "/metrics", "/manage", "/management", "/health", "/version", "/info", "/env", "/logs",
                    "/swagger-ui", "/swagger-ui/index.html", "/swagger.json", "/swagger/v1/swagger.json", "/openapi", "/openapi.json", "/v3/api-docs", "/v3/api-docs.yaml",
                    "/graphql", "/graphiql", "/voyager", "/playground",
                    "/.well-known/openid-configuration", "/.well-known/security.txt"
            );
            candidates.addAll(common);
            // на основе OpenAPI — собрать корневые сегменты и их вариации
            Set<String> roots = new HashSet<>();
            for (String p : endpoints) {
                String seg = p.startsWith("/")? p.substring(1): p;
                int idx = seg.indexOf('/'); if (idx>0) seg = seg.substring(0, idx);
                if (!seg.isBlank()) roots.add(seg);
            }
            List<String> suffixes = List.of("/health","/status","/metrics","/debug","/internal","/admin","/v1","/v2","/info");
            for (String rseg : roots) {
                for (String sfx : suffixes) candidates.add("/"+rseg+sfx);
            }
            // лимит по профилю
            int maxProbe = switch (pr) { case FAST -> 30; case AGGRESSIVE -> 200; default -> 80; };
            int[] count = {0};
            for (String p : candidates) {
                if (count[0]++ >= maxProbe) break;
                tasks.add(() -> {
                    String url = (targetBase.endsWith("/")? targetBase.substring(0, targetBase.length()-1): targetBase) + p;
                    try (Response r = http.request("GET", url, null, null)) {
                        if (r.code() != 404 && !known.contains(p)) {
                            ReportModel.Undocumented u = new ReportModel.Undocumented();
                            u.path = p; u.method = "GET"; u.status = r.code();
                            u.evidence = "GET "+p+" => "+r.code();
                            u.traceRef = saveFullTrace(url, "GET", null, r);
                            synchronized (report.contract.undocumented){ report.contract.undocumented.add(u);} 
                        }
                    } catch (Exception ignored) {}
                    return null;
                });
                tasks.add(() -> {
                    String url = (targetBase.endsWith("/")? targetBase.substring(0, targetBase.length()-1): targetBase) + p;
                    try (Response r = http.request("OPTIONS", url, null, null)) {
                        if (r.code() >= 200 && r.code() < 500 && !known.contains(p)) {
                            ReportModel.Undocumented u = new ReportModel.Undocumented();
                            u.path = p; u.method = "OPTIONS"; u.status = r.code();
                            u.evidence = "OPTIONS "+p+" => "+r.code();
                            u.traceRef = saveFullTrace(url, "OPTIONS", null, r);
                            synchronized (report.contract.undocumented){ report.contract.undocumented.add(u);} 
                        }
                    } catch (Exception ignored) {}
                    return null;
                });
            }
        }

        List<SPI> scanners = List.of(
                new CorsHeadersScanner(),
                new SecurityHeadersScanner(),
                new WeakAuthScanner(),
                new BolaIdorScanner(),
                new InjectionScanner(),
                new ExcessiveDataScanner(),
                new RateLimitScanner(),
                new MassAssignmentScanner(),
                new VerboseErrorsScanner(),
                new BflaScanner(),
                new HppScanner(),
                new PaginationScanner(),
                new MethodOverrideScanner()
        );
        int idorMax = switch (pr) { case FAST -> 2; case AGGRESSIVE -> 12; default -> 6; };
        int injOps  = switch (pr) { case FAST -> 6; case AGGRESSIVE -> 30; default -> 15; };
        int burst   = switch (pr) { case FAST -> 5; case AGGRESSIVE -> 40; default -> 15; };
        report.telemetry.presetParams.put("idorMax", idorMax);
        report.telemetry.presetParams.put("injectionOps", injOps);
        report.telemetry.presetParams.put("rateBurst", burst);
        if (publicPaths == null) publicPaths = new ArrayList<>();
        String depth = exploitDepth;
        if (depth == null || depth.isBlank()) {
            depth = switch (pr) { case FAST -> "low"; case AGGRESSIVE -> "high"; default -> "med"; };
        }
        SPI.ScanContext sctx = new SPI.ScanContext(targetBase, http, log, report, debug, spec.root, endpoints, pr.name().toLowerCase(), idorMax, injOps, burst,
                (url, method, reqBody, resp) -> saveFullTrace(url, method, reqBody, resp), publicPaths, allowCorsWildcardPublic,
                depth, maxExploitOps, safetySkipDelete);
        for (SPI sc : scanners) {
            tasks.add(() -> {
                long t0 = System.nanoTime();
                log.info("Старт сканера: "+sc.getCategory());
                try { sc.run(sctx).get(); }
                catch (Exception e) { log.error("Ошибка сканера "+sc.getCategory(), e); }
                long dt = (System.nanoTime()-t0)/1_000_000L;
                synchronized (report.telemetry) {
                    report.telemetry.scannerAttempts.merge(sc.getCategory(), 1, Integer::sum);
                    report.telemetry.scannerDurMs.merge(sc.getCategory(), dt, Long::sum);
                }
                log.info("Завершён сканер: "+sc.getCategory()+", длительность="+dt+" мс");
                return null;
            });
        }

        pool.invokeAll(tasks, dur.toMillis(), TimeUnit.MILLISECONDS);
        pool.shutdownNow();

        int eps = ops.size();
        report.meta.endpointsScanned = eps;
        report.telemetry.presetParams.put("operationsPlanned", eps);
        if (report.telemetry.requestsTotal > 0) {
            report.telemetry.avgLatencyMs = report.telemetry.avgLatencyMs / (double) report.telemetry.requestsTotal;
        }
        report.telemetry.contractMismatchRate = eps == 0 ? 0 : (double) report.contract.mismatches.size() / (double) eps;
        Map<String, Integer> counts = new HashMap<>();
        for (ReportModel.SecurityIssue si : report.security) counts.merge(si.category, 1, Integer::sum);
        report.telemetry.vulnCounts = counts;

        Instant finished = Instant.now();
        report.meta.finishedAt = finished.toString();
        report.meta.durationMs = Duration.between(started, finished).toMillis();

        // OWASP Risk Rating: compute for each issue; update severity and append to description
        for (ReportModel.SecurityIssue si : report.security) {
            try {
                RiskAssessor.Risk risk = RiskAssessor.compute(si);
                // Align severity with risk rating
                si.severity = risk.rating;
                String marker = String.format(" [OWASP Risk: %s (L=%.1f, I=%.1f, S=%.1f)]", risk.rating, risk.likelihood, risk.impact, risk.score);
                if (si.description == null) si.description = "";
                if (!si.description.contains("OWASP Risk:")) si.description += marker;
            } catch (Exception ignored) {}
        }

        ReportWriter writer = new ReportWriter();
        writer.writeJson(report, reportJson);
        writer.writeHtml(report, reportHtml);
        writer.writePdf(report, reportPdf);

        // Optional anonymous telemetry
        if (telemetryOptIn && telemetryEndpoint != null && !telemetryEndpoint.isBlank()) {
            try {
                okhttp3.OkHttpClient c = new okhttp3.OkHttpClient.Builder().callTimeout(java.time.Duration.ofSeconds(5)).build();
                com.fasterxml.jackson.databind.ObjectMapper om = new com.fasterxml.jackson.databind.ObjectMapper();
                String payload = om.writeValueAsString(report.telemetry);
                okhttp3.Request req = new okhttp3.Request.Builder()
                        .url(telemetryEndpoint)
                        .post(okhttp3.RequestBody.create(payload, okhttp3.MediaType.parse("application/json")))
                        .build();
                c.newCall(req).execute().close();
            } catch (Exception ignored) {}
        }

        log.info("Сканирование завершено. Эндпоинтов: "+eps+", запросов: "+report.telemetry.requestsTotal+", длительность: "+report.meta.durationMs+" мс");
        return 0;
    }

    private static void validateJson(JsonNode node, JsonNode schema, String path, List<String> errs) {
        if (schema == null || schema.isMissingNode()) return;
        if (schema.has("$ref")) {
            String ref = schema.get("$ref").asText();
            JsonNode resolved = resolveRef(ref);
            if (resolved != null) { schema = resolved; }
        }
        if (schema.has("oneOf") && schema.get("oneOf").isArray()) {
            boolean ok = false;
            for (JsonNode it : schema.get("oneOf")) {
                List<String> sub = new ArrayList<>();
                validateJson(node, it, path, sub);
                if (sub.isEmpty()) { ok = true; break; }
            }
            if (!ok) errs.add(path+": oneOf не выполнен");
            return;
        }
        if (schema.has("anyOf") && schema.get("anyOf").isArray()) {
            boolean ok = false;
            for (JsonNode it : schema.get("anyOf")) {
                List<String> sub = new ArrayList<>();
                validateJson(node, it, path, sub);
                if (sub.isEmpty()) { ok = true; break; }
            }
            if (!ok) errs.add(path+": anyOf не выполнен");
            return;
        }
        if (schema.has("allOf") && schema.get("allOf").isArray()) {
            for (JsonNode it : schema.get("allOf")) {
                validateJson(node, it, path, errs);
            }
        }
        String type = schema.path("type").asText(null);
        if (type != null) {
            switch (type) {
                case "object" -> {
                    if (!node.isObject()) { errs.add(path+": ожидается object"); return; }
                    JsonNode props = schema.path("properties");
                    JsonNode required = schema.path("required");
                    boolean additional = schema.path("additionalProperties").asBoolean(true);
                    if (required.isArray()) {
                        required.forEach(r -> { if (!node.has(r.asText())) errs.add(path+": отсутствует обязательное поле "+r.asText()); });
                    }
                    if (!additional && props.isObject()) {
                        node.fieldNames().forEachRemaining(fn -> { if (!props.has(fn)) errs.add(path+": лишнее поле "+fn); });
                    }
                    if (props.isObject()) {
                        props.fieldNames().forEachRemaining(fn -> {
                            if (node.has(fn)) validateJson(node.get(fn), props.get(fn), path+"."+fn, errs);
                        });
                    }
                }
                case "array" -> {
                    if (!node.isArray()) { errs.add(path+": ожидается array"); return; }
                    JsonNode items = schema.path("items");
                    for (int i=0;i<node.size();i++) validateJson(node.get(i), items, path+"["+i+"]", errs);
                }
                case "string" -> { if (!node.isTextual()) errs.add(path+": ожидается string"); }
                case "integer" -> { if (!node.isIntegralNumber()) errs.add(path+": ожидается integer"); }
                case "number" -> { if (!node.isNumber()) errs.add(path+": ожидается number"); }
                case "boolean" -> { if (!node.isBoolean()) errs.add(path+": ожидается boolean"); }
            }
        }
    }

    private static JsonNode resolveRef(String ref) {
        if (ref == null || !ref.startsWith("#")) return null;
        String[] parts = ref.substring(2).split("/");
        JsonNode cur = cachedSpecRoot;
        for (String p : parts) {
            if (cur == null) return null;
            cur = cur.path(p);
        }
        return cur;
    }

    private static int scoreOp(String path, String method, List<String> hot) {
        int s = 0;
        String p = path.toLowerCase();
        for (String k : hot) if (p.contains(k)) s += 5;
        if (!"get".equalsIgnoreCase(method)) s += 2; // модифицирующие методы важнее
        return s;
    }

    private String saveFullTrace(String url, String method, String reqBody, Response r) {
        try {
            String name = method+"_"+ url.replaceAll("[^a-zA-Z0-9]+","_") +"_"+r.code()+"_"+System.currentTimeMillis()+".json";
            Path file = tracesDir.resolve(name);
            Files.createDirectories(tracesDir);
            Map<String,Object> tr = new LinkedHashMap<>();
            tr.put("url", url);
            tr.put("method", method);
            Map<String,String> reqH = new LinkedHashMap<>();
            r.request().headers().names().forEach(h -> reqH.put(h, ru.apidefender.core.http.Masking.maskHeader(h, r.request().header(h))));
            tr.put("requestHeaders", reqH);
            if (reqBody != null) tr.put("requestBody", ru.apidefender.core.http.Masking.maskSecrets(reqBody));
            Map<String,String> resH = new LinkedHashMap<>();
            r.headers().names().forEach(h -> resH.put(h, ru.apidefender.core.http.Masking.maskHeader(h, r.header(h))));
            tr.put("status", r.code());
            tr.put("responseHeaders", resH);
            String body = r.peekBody(5_000_000).string();
            tr.put("responseBody", ru.apidefender.core.http.Masking.maskSecrets(body));
            new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(file.toFile(), tr);
            return file.getFileName().toString();
        } catch (Exception e) {
            return UUID.randomUUID().toString();
        }
    }
}
