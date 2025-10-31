package ru.apidefender.gui;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

public class ServerMain {
    static class ScanRequest {
        public String openapi = "/app/specs/openapi.json";
        public String baseUrl;
        public String tokenFile = "/secrets/token.jwt";
        public String preset = "full";
        public String timeout = "5m";
        public Integer concurrency;
        public String reportHtml;
        public String reportPdf;
        public String reportJson;
        public String tracesDir;
        public String logFile;
        public String logLevel = "info";
        public boolean discoverUndocumented = true;
        public boolean strictContract = true;
        public List<String> publicPaths;
        public Boolean allowCorsWildcardPublic;
        public String exploitDepth;
        public Integer maxExploitOps;
        public Boolean safetySkipDelete;
    }
    static class ScanStatus {
        public String id;
        public String status; // queued|running|finished|error
        public String startedAt;
        public Long elapsedMs;
        public Map<String,Boolean> reportsExist = new HashMap<>();
        public List<String> lastLogLines = new ArrayList<>();
        public String error;
    }

    static class Scan {
        final String id;
        final Path outDir;
        final Path reportsHtml;
        final Path reportsPdf;
        final Path reportsJson;
        final Path logFile;
        final Process process;
        final long started;
        Scan(String id, Path outDir, Path reportsHtml, Path reportsPdf, Path reportsJson, Path logFile, Process process){
            this.id=id; this.outDir=outDir; this.reportsHtml=reportsHtml; this.reportsPdf=reportsPdf; this.reportsJson=reportsJson; this.logFile=logFile; this.process=process; this.started=System.currentTimeMillis();
        }
    }

    static final Map<String, Scan> scans = new ConcurrentHashMap<>();
    static final ObjectMapper om = new ObjectMapper();
    static Path webRoot = Paths.get(Optional.ofNullable(System.getenv("WEB_ROOT")).orElse("/app/web"));

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(Optional.ofNullable(System.getenv("PORT")).orElse("8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/api/config", json(ServerMain::handleConfig)); server.createContext("/api/scans", json(ServerMain::handleScans));
        server.createContext("/api/scan", json(ServerMain::handleScan));
        server.createContext("/api/progress", json(ServerMain::handleProgress));
        server.createContext("/api/report", ServerMain::handleReport);
        server.createContext("/", ServerMain::handleStatic);
        server.setExecutor(Executors.newCachedThreadPool());
        System.out.println("GUI server listening on http://0.0.0.0:"+port);
        server.start();
    }

    interface JsonHandler { Object handle(HttpExchange ex) throws Exception; }

    static HttpHandler json(JsonHandler h){
        return ex -> {
            try {
                enableCORS(ex);
                if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) { ex.sendResponseHeaders(204, -1); return; }
                Object result = h.handle(ex);
                byte[] body = om.writerWithDefaultPrettyPrinter().writeValueAsBytes(result);
                ex.getResponseHeaders().add("Content-Type","application/json; charset=utf-8");
                ex.sendResponseHeaders(200, body.length);
                try (OutputStream os = ex.getResponseBody()) { os.write(body); }
            } catch (Exception e){
                e.printStackTrace();
                byte[] b = ("{\"error\":\""+escape(e.getMessage())+"\"}").getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().add("Content-Type","application/json; charset=utf-8");
                ex.sendResponseHeaders(500, b.length);
                try (OutputStream os = ex.getResponseBody()) { os.write(b); }
            } finally { ex.close(); }
        }; }

    static void enableCORS(HttpExchange ex){
        Headers h = ex.getResponseHeaders();
        h.add("Access-Control-Allow-Origin","*");
        h.add("Access-Control-Allow-Methods","GET,POST,OPTIONS");
        h.add("Access-Control-Allow-Headers","Content-Type");
    }

    static Object handleConfig(HttpExchange ex){
        Map<String,Object> cfg = new HashMap<>();
        cfg.put("presets", List.of("fast","full","aggressive"));
        cfg.put("logLevels", List.of("info","debug"));
        cfg.put("exploitDepth", List.of("low","med","high"));
        cfg.put("servers", List.of(
                "https://vbank.open.bankingapi.ru/",
                "https://abank.open.bankingapi.ru/",
                "https://sbank.open.bankingapi.ru/"
        ));
        Map<String,Object> defaults = new HashMap<>();
        defaults.put("openapi","/app/specs/openapi.json");
        defaults.put("tokenFile","/secrets/token.jwt");
        defaults.put("preset","full");
        defaults.put("timeout","5m");
        defaults.put("discoverUndocumented", true);
        defaults.put("strictContract", true);
        cfg.put("defaults", defaults);
        Map<String,String> help = new LinkedHashMap<>();
        help.put("openapi","Путь к OpenAPI (JSON/YAML) внутри контейнера");
        help.put("tokenFile","Путь к файлу с JWT (Bearer)");
        help.put("baseUrl","Базовый URL тестируемого API");
        help.put("preset","Профиль глубины: fast|full|aggressive");
        help.put("timeout","Лимит времени, например 5m, 30s");
        help.put("publicPaths","Пути без авторизации (CSV)");
        help.put("allowCorsWildcardPublic","Разрешить CORS * для public путей");
        help.put("logLevel","Уровень логирования: info|debug");
        help.put("discoverUndocumented","Пробовать найти неописанные пути");
        help.put("strictContract","Строго проверять контракт");
        help.put("exploitDepth","Глубина эксплуатаций: low|med|high");
        help.put("maxExploitOps","Ограничение количества операций эксплуатации");
        help.put("safetySkipDelete","Пропускать опасные DELETE");
        cfg.put("help", help);
        return cfg;
    }

    static Object handleScan(HttpExchange ex) throws Exception {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) throw new RuntimeException("POST required");
        ScanRequest req = readJson(ex, ScanRequest.class);
        if (req.baseUrl == null || req.baseUrl.isBlank()) throw new RuntimeException("baseUrl is required");
        String id = UUID.randomUUID().toString();
        Path outDir = Paths.get(Optional.ofNullable(req.tracesDir).orElse("/out")).resolve("gui_scans").resolve(id);
        Files.createDirectories(outDir);
        Path html = outDir.resolve("report.html");
        Path pdf  = outDir.resolve("report.pdf");
        Path json = outDir.resolve("report.json");
        Path log  = outDir.resolve("scan.log");
        List<String> cmd = new ArrayList<>();
        cmd.add("apidefender");
        cmd.add("scan");
        cmd.addAll(List.of("--openapi", req.openapi));
        cmd.addAll(List.of("--token-file", req.tokenFile));
        cmd.addAll(List.of("--base-url", req.baseUrl));
        if (req.preset != null) cmd.addAll(List.of("--preset", req.preset));
        if (req.timeout != null) cmd.addAll(List.of("--timeout", req.timeout));
        if (req.concurrency != null) cmd.addAll(List.of("--concurrency", String.valueOf(req.concurrency)));
        cmd.addAll(List.of("--report-html", html.toString()));
        cmd.addAll(List.of("--report-pdf",  pdf.toString()));
        cmd.addAll(List.of("--report-json", json.toString()));
        cmd.addAll(List.of("--save-traces", outDir.resolve("traces").toString()));
        cmd.addAll(List.of("--log-file", log.toString()));
        if (req.logLevel != null) cmd.addAll(List.of("--log-level", req.logLevel));
        if (req.discoverUndocumented) cmd.add("--discover-undocumented");
        if (req.strictContract) cmd.add("--strict-contract");
        if (req.publicPaths != null && !req.publicPaths.isEmpty()) cmd.addAll(List.of("--public-path", String.join(",", req.publicPaths)));
        if (req.allowCorsWildcardPublic != null && req.allowCorsWildcardPublic) cmd.add("--allow-cors-wildcard-public");
        if (req.exploitDepth != null) cmd.addAll(List.of("--exploit-depth", req.exploitDepth));
        if (req.maxExploitOps != null) cmd.addAll(List.of("--max-exploit-ops", String.valueOf(req.maxExploitOps)));
        if (req.safetySkipDelete != null && req.safetySkipDelete) cmd.add("--safety-skip-delete");

        ProcessBuilder pb = new ProcessBuilder(cmd);
        Map<String,String> env = pb.environment();
        pb.redirectErrorStream(true);
        pb.redirectOutput(ProcessBuilder.Redirect.appendTo(log.toFile()));
        Process p = pb.start();
        scans.put(id, new Scan(id, outDir, html, pdf, json, log, p));
        Map<String,Object> resp = new HashMap<>();
        resp.put("id", id);
        resp.put("startedAt", Instant.now().toString());
        resp.put("reports", Map.of(
                "html", "/api/report/"+id+"/html",
                "pdf",  "/api/report/"+id+"/pdf",
                "json", "/api/report/"+id+"/json"
        ));
        resp.put("logFile", "/api/report/"+id+"/log");
        return resp;
    }

    static Object handleProgress(HttpExchange ex) throws Exception {
        Map<String, String> q = splitQuery(ex.getRequestURI());
        String id = q.get("id");
        if (id == null) throw new RuntimeException("id is required");
        Scan sc = scans.get(id);
        if (sc == null) throw new RuntimeException("unknown id");
        ScanStatus st = new ScanStatus();
        st.id = id;
        st.startedAt = Instant.ofEpochMilli(sc.started).toString();
        st.elapsedMs = System.currentTimeMillis() - sc.started;
        boolean html = Files.exists(sc.reportsHtml);
        boolean pdf = Files.exists(sc.reportsPdf);
        boolean json = Files.exists(sc.reportsJson);
        st.reportsExist.put("html", html);
        st.reportsExist.put("pdf", pdf);
        st.reportsExist.put("json", json);
        if (sc.process.isAlive()) st.status = "running"; else st.status = (html || pdf || json)? "finished" : "error";
        st.lastLogLines = tail(sc.logFile, 100);
        // copy reports to stable folder when finished
        if ("finished".equals(st.status)) {
            try {
                Path stable = Paths.get("/out").resolve("reports").resolve(id);
                Files.createDirectories(stable);
                if (Files.exists(sc.reportsHtml)) Files.copy(sc.reportsHtml, stable.resolve("report.html"), StandardCopyOption.REPLACE_EXISTING);
                if (Files.exists(sc.reportsPdf)) Files.copy(sc.reportsPdf, stable.resolve("report.pdf"), StandardCopyOption.REPLACE_EXISTING);
                if (Files.exists(sc.reportsJson)) Files.copy(sc.reportsJson, stable.resolve("report.json"), StandardCopyOption.REPLACE_EXISTING);
                if (Files.exists(sc.logFile)) Files.copy(sc.logFile, stable.resolve("scan.log"), StandardCopyOption.REPLACE_EXISTING);
            } catch (Exception ignored) {}
        }
        return st;
    }

    static Object handleScans(HttpExchange ex) throws Exception {
        List<Map<String,Object>> list = new ArrayList<>();
        Path root = Paths.get("/out").resolve("gui_scans");
        if (Files.exists(root)) {
            try (var ds = Files.newDirectoryStream(root)){
                for (Path p : ds) {
                    if (!Files.isDirectory(p)) continue;
                    Map<String,Object> it = new LinkedHashMap<>();
                    String id = p.getFileName().toString();
                    it.put("id", id);
                    it.put("dir", "/out/gui_scans/"+id);
                    it.put("reportHtml", Files.exists(p.resolve("report.html")));
                    it.put("reportPdf", Files.exists(p.resolve("report.pdf")));
                    it.put("reportJson", Files.exists(p.resolve("report.json")));
                    list.add(it);
                }
            }
        }
        return list;
    }

    static void handleReport(HttpExchange ex) throws IOException {
        enableCORS(ex);
        URI uri = ex.getRequestURI();
        String path = uri.getPath(); // /api/report/{id}/{type}
        String[] parts = path.split("/");
        if (parts.length < 5) { send404(ex); return; }
        String id = parts[3]; String type = parts[4];
        Scan sc = scans.get(id);
        if (sc == null) { send404(ex); return; }
        Path file;
        String ctype;
        switch (type){
            case "html" -> { file = sc.reportsHtml; ctype = "text/html; charset=utf-8"; }
            case "pdf" -> { file = sc.reportsPdf; ctype = "application/pdf"; }
            case "json" -> { file = sc.reportsJson; ctype = "application/json"; }
            case "log" -> { file = sc.logFile; ctype = "text/plain; charset=utf-8"; }
            default -> { send404(ex); return; }
        }
        if (!Files.exists(file)) { send404(ex); return; }
        byte[] body = Files.readAllBytes(file);
        ex.getResponseHeaders().add("Content-Type", ctype);
        ex.sendResponseHeaders(200, body.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(body); }
        ex.close();
    }

    static void handleStatic(HttpExchange ex) throws IOException {
        enableCORS(ex);
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) { ex.sendResponseHeaders(405, -1); return; }
        String p = ex.getRequestURI().getPath();
        if (p.equals("/")) p = "/index.html";
        Path file = webRoot.resolve(p.substring(1));
        if (!Files.exists(file)) {
            // SPA fallback
            file = webRoot.resolve("index.html");
        }
        String ctype = contentType(file.getFileName().toString());
        byte[] body = Files.readAllBytes(file);
        ex.getResponseHeaders().add("Content-Type", ctype);
        ex.sendResponseHeaders(200, body.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(body); }
        ex.close();
    }

    static <T> T readJson(HttpExchange ex, Class<T> cls) throws IOException {
        try (InputStream is = ex.getRequestBody()){
            return om.readValue(is, cls);
        }
    }

    static List<String> tail(Path file, int lines){
        List<String> out = new ArrayList<>();
        try {
            if (!Files.exists(file)) return out;
            List<String> all = Files.readAllLines(file, StandardCharsets.UTF_8);
            int from = Math.max(0, all.size()-lines);
            for (int i=from;i<all.size();i++) out.add(all.get(i));
        } catch (Exception ignored) {}
        return out;
    }

    static Map<String,String> splitQuery(URI uri){
        Map<String,String> m = new HashMap<>();
        String q = uri.getRawQuery();
        if (q == null) return m;
        for (String kv : q.split("&")){
            int i = kv.indexOf('=');
            if (i>0) m.put(urlDecode(kv.substring(0,i)), urlDecode(kv.substring(i+1)));
        }
        return m;
    }

    static String urlDecode(String s){ try { return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8); } catch (Exception e){ return s; } }
    static String escape(String s){ return s==null?"":s.replace("\"","\\\""); }
    static void send404(HttpExchange ex) throws IOException { ex.sendResponseHeaders(404, -1); ex.close(); }
    static String contentType(String name){
        String n = name.toLowerCase(Locale.ROOT);
        if (n.endsWith(".html")) return "text/html; charset=utf-8";
        if (n.endsWith(".js")) return "text/javascript; charset=utf-8";
        if (n.endsWith(".css")) return "text/css; charset=utf-8";
        if (n.endsWith(".json")) return "application/json";
        if (n.endsWith(".png")) return "image/png";
        if (n.endsWith(".svg")) return "image/svg+xml";
        return "application/octet-stream";
    }
}

