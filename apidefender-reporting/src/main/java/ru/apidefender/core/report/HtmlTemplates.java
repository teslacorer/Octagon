package ru.apidefender.core.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class HtmlTemplates {
    public static String render(ReportModel r) {
        Map<String,Integer> sevCounts = new HashMap<>();
        for (ReportModel.SecurityIssue si : r.security) sevCounts.merge(si.severity, 1, Integer::sum);
        String sevSummary = sevCounts.entrySet().stream()
                .map(e -> "<span class='sev sev-"+cls(e.getKey())+"'>"+escape(e.getKey())+": "+e.getValue()+"</span>")
                .collect(Collectors.joining(" &#160; "));

        String issues = r.security.stream().map(i -> {
            String details = renderDetails(r.meta.tracesDir, i.traceRef);
            return "<tr class='sev-"+cls(i.severity)+"'>"+
                    td(escape(i.category))+
                    td(escape(i.severity))+
                    td(escape(i.method+" "+i.endpoint))+
                    td(escape(i.description))+
                    td(details)+
                    "</tr>";
        }).collect(Collectors.joining());

        String mism = r.contract.mismatches.stream().map(m -> "<tr>"+td(escape(m.method))+td(escape(m.endpoint))+td(escape(m.issue))+"</tr>").collect(Collectors.joining());
        String und = r.contract.undocumented.stream().map(u -> "<tr>"+td(escape(u.method))+td(escape(u.path))+td(Integer.toString(u.status))+"</tr>").collect(Collectors.joining());

        String preset = escape(nullToEmpty(r.meta.preset));
        String tel1 = r.telemetry.vulnCounts.entrySet().stream().map(e->"<li>"+escape(e.getKey())+": "+e.getValue()+"</li>").collect(Collectors.joining());
        String tel2 = r.telemetry.scannerDurMs.entrySet().stream().map(e->"<li>"+escape(e.getKey())+": "+e.getValue()+" мс</li>").collect(Collectors.joining());
        String tel3 = r.telemetry.presetParams.entrySet().stream().map(e->"<li>"+escape(e.getKey())+": "+escape(String.valueOf(e.getValue()))+"</li>").collect(Collectors.joining());

        // HTML-only: derive slowest endpoints from RateLimit evidence
        java.util.List<String> slow = new java.util.ArrayList<>();
        for (ReportModel.SecurityIssue si : r.security) {
            if ("RateLimit".equals(si.category)) {
                String ev = si.evidence != null? si.evidence : "";
                long t5000 = parseLatency(ev, "t5000=");
                slow.add(si.endpoint+" ("+t5000+" ms)");
            }
        }
        java.util.List<String> topSlow = slow.stream().sorted((a,b) -> {
            long va = parseTailLatency(a); long vb = parseTailLatency(b);
            return Long.compare(vb, va);
        }).limit(5).collect(java.util.stream.Collectors.toList());
        String slowHtml = topSlow.stream().map(s->"<li>"+escape(s)+"</li>").collect(java.util.stream.Collectors.joining());

        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"ru\">"
                + "<head>"
                + "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />"
                + "<title>Отчет API Defender</title>"
                + "<style type=\"text/css\">"
                + "body{font-family:sans-serif} table{border-collapse:collapse;width:100%} td,th{border:1px solid #ccc;padding:6px}"
                + ".sev{padding:3px 6px;border-radius:4px;color:#fff}"
                + ".sev-low{background:#2e7d32} .sev-medium{background:#f9a825} .sev-high{background:#ef6c00} .sev-critical{background:#c62828}"
                + "tr.sev-low{background:#e8f5e9} tr.sev-medium{background:#fff8e1} tr.sev-high{background:#fff3e0} tr.sev-critical{background:#ffebee}"
                + "details summary{cursor:pointer;color:#1565c0} pre{white-space:pre-wrap;background:#f6f8fa;padding:8px;border-radius:4px}"
                + "</style>"
                + "</head><body>"
                + "<h1>Отчет API Defender</h1>"
                + "<p><b>Цель:</b> "+escape(nullToEmpty(r.meta.target))+"<br/><b>Профиль:</b> "+preset+"<br/><b>Длительность:</b> "+r.meta.durationMs+" мс</p>"
                + "<h2>Итоги</h2>"
                + "<p><b>По уровням серьезности:</b> "+sevSummary+"</p>"
                + "<p><b>Найдены уязвимости по категориям:</b><ul>"+tel1+"</ul>"
                + "<b>Время работы сканеров:</b><ul>"+tel2+"</ul>"
                + "<b>Параметры профиля:</b><ul>"+tel3+"</ul>"
                + (slowHtml.isBlank()? "" : "<b>Самые медленные (по t5000):</b><ul>"+slowHtml+"</ul>")
                + "</p>"
                + "<h2>Несоответствия контракту</h2><table><tr><th>Метод</th><th>Путь</th><th>Описание</th></tr>"+mism+"</table>"
                + "<h2>Неописанные эндпоинты</h2><table><tr><th>Метод</th><th>Путь</th><th>Статус</th></tr>"+und+"</table>"
                + "<h2>Уязвимости</h2><table><tr><th>Категория</th><th>Серьезность</th><th>Метод</th><th>Описание</th><th>Детали</th></tr>"+issues+"</table>"
                + "</body></html>";
    }

    private static String renderDetails(String tracesDir, String traceRef) {
        if (traceRef == null) return "";
        try {
            Path base = tracesDir != null? Path.of(tracesDir) : null;
            Path file = base != null? base.resolve(traceRef) : null;
            if (file != null && Files.isRegularFile(file)) {
                ObjectMapper om = new ObjectMapper();
                JsonNode t = om.readTree(Files.readString(file));
                String req = "";
                if (t.has("method") && t.has("url")) req += t.get("method").asText()+" "+t.get("url").asText()+"\n";
                if (t.has("requestHeaders")) req += prettyKV(t.get("requestHeaders"));
                if (t.has("requestBody")) req += "\n"+t.get("requestBody").asText();
                String res = "";
                if (t.has("status")) res += "Status: "+t.get("status").asInt()+"\n";
                if (t.has("responseHeaders")) res += prettyKV(t.get("responseHeaders"));
                if (t.has("responseBody")) res += "\n"+t.get("responseBody").asText();
                return "<details><summary>Трейс</summary><div><b>Запрос</b><pre>"+escape(req)+"</pre><b>Ответ</b><pre>"+escape(res)+"</pre><i>Ссылка: "+escape(traceRef)+"</i></div></details>";
            }
        } catch (Exception ignored) {}
        return "<details><summary>Трейс</summary><div><i>Ссылка: "+escape(traceRef)+"</i></div></details>";
    }

    private static String prettyKV(JsonNode obj){
        StringBuilder sb = new StringBuilder();
        obj.fieldNames().forEachRemaining(fn -> {
            sb.append(fn).append(": ").append(obj.get(fn).asText(""));
            sb.append("\n");
        });
        return sb.toString();
    }

    private static String td(String s){ return "<td>"+s+"</td>"; }

    private static String cls(String severity){
        if (severity==null) return "low";
        String s = severity.toLowerCase();
        if (s.contains("critical")) return "critical";
        if (s.contains("high")) return "high";
        if (s.contains("medium")) return "medium";
        return "low";
    }

    private static String escape(String s){
        if (s==null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;");
    }

    private static String nullToEmpty(String s){ return s==null? "": s; }

    private static long parseLatency(String s, String key){
        try {
            int i = s.indexOf(key);
            if (i < 0) return 0L;
            int j = s.indexOf("ms", i);
            String sub = (j > i)? s.substring(i+key.length(), j) : s.substring(i+key.length());
            return Long.parseLong(sub.replaceAll("[^0-9]",""));
        } catch (Exception e){ return 0L; }
    }

    private static long parseTailLatency(String s){
        try {
            int i = s.lastIndexOf('(');
            int j = s.lastIndexOf("ms");
            String sub = (i>=0 && j>i)? s.substring(i+1, j) : "0";
            return Long.parseLong(sub.replaceAll("[^0-9]",""));
        } catch (Exception e){ return 0L; }
    }
}

