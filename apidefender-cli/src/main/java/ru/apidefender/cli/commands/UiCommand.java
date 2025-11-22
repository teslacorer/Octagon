package ru.apidefender.cli.commands;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import picocli.CommandLine;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "ui", description = "Веб‑интерфейс для запуска сканера API Defender")
public class UiCommand implements Callable<Integer> {

  @CommandLine.Option(names = "--port", description = "Порт HTTP‑сервера UI", defaultValue = "8080")
  int port;

  @CommandLine.Option(names = "--openapi-default", description = "Путь к OpenAPI по умолчанию", defaultValue = "/app/specs/openapi.json")
  String openapiDefault;

  @CommandLine.Option(names = "--token-default", description = "Путь к JWT по умолчанию", defaultValue = "/secrets/token.jwt")
  String tokenDefault;

  @CommandLine.Option(names = "--api-key-default", description = "Путь к API‑ключу OpenRouter по умолчанию", defaultValue = "/secrets/api_key.txt")
  String apiKeyDefault;

  @CommandLine.Option(names = "--ai-timeout-default", description = "Таймаут работы AI (например, 50s)", defaultValue = "50s")
  String aiTimeoutDefault;

  @Override
  public Integer call() throws Exception {
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/", this::handleIndex);
    server.createContext("/scan", this::handleScan);
    server.createContext("/report", this::handleReport);
    server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
    System.out.println("API Defender UI запущен: http://localhost:" + port + "/");
    server.start();

    try {
      // держим процесс живым, пока его не остановят снаружи
      // noinspection InfiniteLoopStatement
      while (true) {
        Thread.sleep(60_000L);
      }
    } catch (InterruptedException e) {
      server.stop(0);
      Thread.currentThread().interrupt();
      return 0;
    }
  }

  private void handleIndex(HttpExchange exchange) throws IOException {
    if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
      exchange.sendResponseHeaders(405, -1);
      return;
    }
    String html = buildIndexPage();
    Headers h = exchange.getResponseHeaders();
    h.set("Content-Type", "text/html; charset=utf-8");
    byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(200, bytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bytes);
    }
  }

  private void handleScan(HttpExchange exchange) throws IOException {
    if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
      exchange.sendResponseHeaders(405, -1);
      return;
    }
    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    Map<String, String> form = parseForm(body);

    List<String> args = new ArrayList<>();

    // OpenAPI
    String openapi = form.getOrDefault("openapi", "").trim();
    if (openapi.isEmpty()) {
      openapi = openapiDefault;
    }
    args.add("--openapi");
    args.add(openapi);

    // JWT
    String token = form.getOrDefault("token", "").trim();
    if (token.isEmpty()) {
      token = tokenDefault;
    }
    args.add("--token-file");
    args.add(token);

    // Пресет
    String preset = form.getOrDefault("preset", "aggressive").trim();
    if (!preset.isEmpty()) {
      args.add("--preset");
      args.add(preset);
    }

    // Таймаут всего скана
    String timeout = form.getOrDefault("timeout", "5m").trim();
    if (!timeout.isEmpty()) {
      args.add("--timeout");
      args.add(timeout);
    }

    // Всегда пишем вывод в /out внутри контейнера (мапится в локальный ./out)
    args.add("--report-html");
    args.add("/out/report.html");
    args.add("--report-pdf");
    args.add("/out/report.pdf");
    args.add("--report-json");
    args.add("/out/report.json");
    args.add("--save-traces");
    args.add("/out/traces");
    args.add("--log-file");
    args.add("/out/scan.log");

    // AI
    boolean aiEnabled = "on".equalsIgnoreCase(form.getOrDefault("aiEnabled", ""));
    if (aiEnabled) {
      args.add("--ai-enabled");
      String aiKey = form.getOrDefault("aiKey", "").trim();
      if (aiKey.isEmpty()) {
        aiKey = apiKeyDefault;
      }
      args.add("--ai-key-file");
      args.add(aiKey);

      String aiModel = form.getOrDefault("aiModel", "").trim();
      if (!aiModel.isEmpty()) {
        args.add("--ai-model");
        args.add(aiModel);
      }

      String aiTimeout = form.getOrDefault("aiTimeout", "").trim();
      if (aiTimeout.isEmpty()) {
        aiTimeout = aiTimeoutDefault;
      }
      if (!aiTimeout.isEmpty()) {
        args.add("--ai-timeout");
        args.add(aiTimeout);
      }
    }

    int exitCode;
    try {
      exitCode = new CommandLine(new ScanCommand()).execute(args.toArray(new String[0]));
    } catch (Exception e) {
      String html = "<html><head><meta charset=\"utf-8\"/>" +
          "<title>API Defender UI — ошибка</title></head><body>" +
          "<h1>Ошибка запуска сканирования</h1>" +
          "<pre>" + escape(e.toString()) + "</pre>" +
          "<p><a href=\"/\">Вернуться назад</a></p>" +
          "</body></html>";
      byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
      exchange.sendResponseHeaders(500, bytes.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(bytes);
      }
      return;
    }

    String resultMsg = exitCode == 0
        ? "Сканирование успешно завершено."
        : "Сканирование завершено с кодом " + exitCode + ".";

    String html = "<html><head><meta charset=\"utf-8\"/>" +
        "<title>API Defender — результат сканирования</title>" +
        "</head><body>" +
        "<h1>" + escape(resultMsg) + "</h1>" +
        "<p><a href=\"/report\" target=\"_blank\">Открыть HTML‑отчёт</a></p>" +
        "<p><a href=\"/\">Новый запуск</a></p>" +
        "</body></html>";

    byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
    exchange.sendResponseHeaders(200, bytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bytes);
    }
  }

  private void handleReport(HttpExchange exchange) throws IOException {
    if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
      exchange.sendResponseHeaders(405, -1);
      return;
    }
    Path report = Path.of("/out", "report.html");
    if (!Files.exists(report)) {
      String html = "<html><head><meta charset=\"utf-8\"/></head><body>" +
          "<h1>Отчёт ещё не сформирован</h1>" +
          "<p>Сначала выполните сканирование через главную страницу UI.</p>" +
          "<p><a href=\"/\">Вернуться</a></p>" +
          "</body></html>";
      byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
      exchange.sendResponseHeaders(404, bytes.length);
      try (OutputStream os = exchange.getResponseBody()) {
        os.write(bytes);
      }
      return;
    }
    byte[] bytes = Files.readAllBytes(report);
    exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
    exchange.sendResponseHeaders(200, bytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bytes);
    }
  }

  private Map<String, String> parseForm(String body) {
    Map<String, String> map = new HashMap<>();
    if (body == null || body.isEmpty())
      return map;
    String[] pairs = body.split("&");
    for (String pair : pairs) {
      int idx = pair.indexOf('=');
      if (idx < 0)
        continue;
      String key = urlDecode(pair.substring(0, idx));
      String val = urlDecode(pair.substring(idx + 1));
      map.put(key, val);
    }
    return map;
  }

  private String urlDecode(String s) {
    return URLDecoder.decode(s, StandardCharsets.UTF_8);
  }

  private String escape(String s) {
    if (s == null)
      return "";
    return s
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;");
  }

  private String buildIndexPage() {
    return """
        <!doctype html>
        <html lang="ru">
        <head>
          <meta charset="utf-8"/>
          <title>API Defender UI</title>
          <meta name="viewport" content="width=device-width, initial-scale=1"/>
          <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
              font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
              background: linear-gradient(135deg,#0f172a,#020617);
              color: #e5e7eb;
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
              padding: 24px;
            }
            .shell { max-width: 960px; width: 100%; }
            .card {
              background: rgba(15,23,42,0.96);
              border-radius: 16px;
              box-shadow: 0 24px 80px rgba(15,23,42,0.9);
              border: 1px solid rgba(148,163,184,0.35);
              overflow: hidden;
            }
            .header {
              padding: 24px 28px 16px;
              border-bottom: 1px solid rgba(148,163,184,0.2);
              display: flex;
              justify-content: space-between;
              align-items: center;
              gap: 12px;
            }
            .title { font-size: 24px; font-weight: 600; }
            .subtitle { font-size: 13px; color: #9ca3af; margin-top: 4px; }
            .badge {
              font-size: 11px;
              text-transform: uppercase;
              letter-spacing: .08em;
              padding: 4px 10px;
              border-radius: 999px;
              border: 1px solid rgba(96,165,250,0.7);
              color: #bfdbfe;
              background: rgba(30,64,175,0.3);
            }
            form {
              display: grid;
              grid-template-columns: repeat(auto-fit,minmax(260px,1fr));
              gap: 16px 20px;
              padding: 20px 28px 22px;
            }
            .field { display: flex; flex-direction: column; gap: 6px; }
            .field label { font-size: 13px; font-weight: 500; }
            .field input, .field select {
              background: #020617;
              border-radius: 8px;
              border: 1px solid rgba(148,163,184,0.5);
              padding: 8px 10px;
              color: #e5e7eb;
              font-size: 13px;
            }
            .field input:focus, .field select:focus {
              outline: none;
              border-color: #60a5fa;
              box-shadow: 0 0 0 1px rgba(37,99,235,0.6);
            }
            .hint {
              font-size: 11px;
              color: #9ca3af;
            }
            .checkbox-row {
              display: flex;
              gap: 8px;
              align-items: center;
              margin-top: 4px;
            }
            .checkbox-row input[type="checkbox"] {
              width: 16px; height: 16px;
            }
            .row-span-2 {
              grid-column: span 1;
            }
            @media (max-width: 720px) {
              .row-span-2 { grid-column: span 1; }
              .header { flex-direction: column; align-items: flex-start; }
            }
            .footer {
              border-top: 1px solid rgba(148,163,184,0.2);
              padding: 14px 24px 16px;
              display: flex;
              justify-content: space-between;
              align-items: center;
              gap: 12px;
            }
            .mono {
              font-size: 11px;
              color: #6b7280;
            }
            .btn {
              border: none;
              border-radius: 999px;
              background: linear-gradient(135deg,#2563eb,#1d4ed8);
              color: #e5e7eb;
              padding: 10px 20px;
              font-size: 13px;
              font-weight: 500;
              cursor: pointer;
              box-shadow: 0 10px 30px rgba(37,99,235,0.55);
              white-space: nowrap;
            }
            .btn:hover {
              background: linear-gradient(135deg,#1d4ed8,#1e40af);
            }
          </style>
        </head>
        <body>
          <div class="shell">
            <div class="card">
              <div class="header">
                <div>
                  <div class="title">API Defender</div>
                  <div class="subtitle">Сканер безопасности API (OpenAPI + OWASP + AI)</div>
                </div>
                <div class="badge">Web UI</div>
              </div>
              <form method="post" action="/scan">
                <div class="field">
                  <label for="openapi">OpenAPI спецификация</label>
                  <input id="openapi" name="openapi" type="text" placeholder="/app/specs/openapi.json" />
                  <div class="hint">Путь к файлу OpenAPI (JSON/YAML). Если оставить пустым, используется /app/specs/openapi.json.</div>
                </div>
                <div class="field">
                  <label for="token">JWT токен</label>
                  <input id="token" name="token" type="text" placeholder="/secrets/token.jwt" />
                  <div class="hint">Путь к файлу с JWT (Authorization: Bearer ...). Если пусто — /secrets/token.jwt.</div>
                </div>

                <div class="field">
                  <label for="preset">Пресет сканирования</label>
                  <select id="preset" name="preset">
                    <option value="fast">fast</option>
                    <option value="full">full</option>
                    <option value="aggressive" selected>aggressive</option>
                  </select>
                  <div class="hint">aggressive — максимально глубокое сканирование (дольше по времени).</div>
                </div>

                <div class="field">
                  <label for="timeout">Таймаут сканирования</label>
                  <input id="timeout" name="timeout" type="text" value="5m" />
                  <div class="hint">Например 5m, 10m, 15m.</div>
                </div>

                <div class="field row-span-2">
                  <label>AI‑анализ отчёта</label>
                  <div class="checkbox-row">
                    <input id="aiEnabled" name="aiEnabled" type="checkbox" />
                    <label for="aiEnabled">Использовать AI (OpenRouter) для приоритизации и рекомендаций</label>
                  </div>
                  <div class="field" style="margin-top:10px;">
                    <label for="aiKey">Файл API‑ключа</label>
                    <input id="aiKey" name="aiKey" type="text" placeholder="/secrets/api_key.txt" />
                    <div class="hint">Если оставить пустым, используется /secrets/api_key.txt.</div>
                  </div>
                  <div class="field" style="margin-top:10px;">
                    <label for="aiModel">Модель</label>
                    <input id="aiModel" name="aiModel" type="text" placeholder="x-ai/grok-4.1-fast" />
                    <div class="hint">По умолчанию x-ai/grok-4.1-fast.</div>
                  </div>
                  <div class="field" style="margin-top:10px;">
                    <label for="aiTimeout">Таймаут AI</label>
                    <input id="aiTimeout" name="aiTimeout" type="text" value="50s" />
                    <div class="hint">Например 50s, 30s и т.п. Если пусто — используется 50s.</div>
                  </div>
                </div>
              </form>
              <div class="footer">
                <div class="mono">
                  URL для проверки берётся из спецификации OpenAPI. Результаты (отчёты и трасы) сохраняются в /out внутри контейнера и должны быть примаплены в ./out на хост‑машине.
                </div>
                <button class="btn" onclick="this.closest('div.card').querySelector('form').submit()">
                  Запустить сканирование
                </button>
              </div>
            </div>
          </div>
        </body>
        </html>
        """;
  }
}
