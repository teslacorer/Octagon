package ru.apidefender.core.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class ReportWriter {
    private final ObjectMapper mapper = new ObjectMapper();

    public void writeJson(ReportModel model, Path path) throws Exception {
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        ReportModel sanitized = sanitizeForSchema(model);
        mapper.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), sanitized);
    }

    // Map non-schema categories to nearest allowed ones for JSON schema compatibility
    private ReportModel sanitizeForSchema(ReportModel model) {
        ReportModel copy = new ReportModel();
        copy.meta = model.meta;
        copy.contract = model.contract;
        copy.telemetry = model.telemetry;
        for (ReportModel.SecurityIssue si : model.security) {
            ReportModel.SecurityIssue x = new ReportModel.SecurityIssue();
            x.id = si.id;
            x.category = mapCategory(si.category);
            x.severity = si.severity;
            x.endpoint = si.endpoint;
            x.method = si.method;
            x.description = si.description;
            x.evidence = si.evidence;
            x.impact = si.impact;
            x.recommendation = si.recommendation;
            x.traceRef = si.traceRef;
            copy.security.add(x);
        }
        return copy;
    }

    private String mapCategory(String c) {
        if (c == null) return null;
        return switch (c) {
            case "HPP" -> "RateLimit"; // best-effort mapping
            case "MethodOverride" -> "WeakAuth";
            case "BFLA" -> "WeakAuth";
            default -> c;
        };
    }

    public void writeHtml(ReportModel model, Path path) throws Exception {
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        String html = HtmlTemplates.render(model);
        html = postProcessHtml(model, html);
        Files.writeString(path, html, StandardCharsets.UTF_8);
    }

    public void writePdf(ReportModel model, Path path) throws Exception {
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        String html = HtmlTemplates.render(model);
        html = postProcessHtml(model, html);
        try (OutputStream os = new FileOutputStream(path.toFile())) {
            PdfRendererBuilder builder = new PdfRendererBuilder();
            builder.useFastMode();
            builder.withHtmlContent(html, null);
            builder.toStream(os);
            builder.run();
        }
    }

    // Injects OWASP Risk header/summary and renames severity header robustly, even with garbled RU strings
    private String postProcessHtml(ReportModel model, String html) {
        try {
            // 1) Build OWASP Risk summary line
            java.util.Map<String,Integer> riskCounts = new java.util.HashMap<>();
            for (ReportModel.SecurityIssue si : model.security) {
                try {
                    ru.apidefender.core.risk.RiskAssessor.Risk rk = ru.apidefender.core.risk.RiskAssessor.compute(si);
                    riskCounts.merge(rk.rating, 1, Integer::sum);
                } catch (Exception ignored) {}
            }
            String riskSummary = riskCounts.entrySet().stream()
                    .map(e -> "<span class='sev sev-"+toCls(e.getKey())+"'>"+escape(e.getKey())+": "+e.getValue()+"</span>")
                    .collect(java.util.stream.Collectors.joining(" &#160; "));

            // 2) Remove first summary paragraph after first <h2> (levels) and insert OWASP Risk paragraph instead
            int h2 = html.indexOf("<h2>");
            if (h2 >= 0) {
                int paraStart = html.indexOf("<p>", h2);
                int paraEnd = paraStart >= 0 ? html.indexOf("</p>", paraStart) : -1;
                if (paraStart >= 0 && paraEnd > paraStart) {
                    String inject = "<p><b>OWASP Risk:</b> "+riskSummary+"</p>";
                    html = html.substring(0, paraStart) + inject + html.substring(paraEnd+4);
                }
            }

            // 3) Replace the last table header row (vulnerabilities) with new headers (remove 'Уровень', add 'Оценка')
            int hdr = html.lastIndexOf("<table><tr><th");
            if (hdr >= 0) {
                int hdrEnd = html.indexOf("</tr>", hdr);
                if (hdrEnd > hdr) {
                    String newHdr = "<table><tr><th>Категория</th><th>Метод/путь</th><th>OWASP Risk</th><th>Оценка</th><th>Описание</th><th>Детали</th></tr>";
                    html = html.substring(0, hdr) + newHdr + html.substring(hdrEnd+5);
                }
            }

            // 4) Rewrite each vulnerability row: drop severity column, add metrics column, clean OWASP marker in description
            int searchPos = 0;
            int issueIndex = 0;
            while (issueIndex < model.security.size()) {
                int rowStart = html.indexOf("<tr class='sev-", searchPos);
                if (rowStart < 0) break;
                int rowEnd = html.indexOf("</tr>", rowStart);
                if (rowEnd < 0) break;

                // Find TD segments (expect at least 6)
                int[] tdStart = new int[6];
                int[] tdEnd = new int[6];
                int cursor = rowStart;
                boolean ok = true;
                for (int k=0;k<6;k++){
                    tdStart[k] = html.indexOf("<td>", cursor);
                    if (tdStart[k] < 0 || tdStart[k] > rowEnd) { ok = false; break; }
                    tdEnd[k] = html.indexOf("</td>", tdStart[k]);
                    if (tdEnd[k] < 0) { ok = false; break; }
                    cursor = tdEnd[k] + 5;
                }
                if (!ok) { searchPos = rowEnd+5; issueIndex++; continue; }

                ReportModel.SecurityIssue si = model.security.get(issueIndex);
                ru.apidefender.core.risk.RiskAssessor.Risk rk = null;
                try { rk = ru.apidefender.core.risk.RiskAssessor.compute(si); } catch (Exception ignored) {}
                String metrics = rk != null ? "Likelihood="+fmt(rk.likelihood)+", Impact="+fmt(rk.impact)+", Score="+fmt(rk.score) : "";

                // Extract pieces
                String td0 = html.substring(tdStart[0], tdEnd[0]+5); // category
                // td1 = severity (drop)
                String td2 = html.substring(tdStart[2], tdEnd[2]+5); // method/path
                String td3 = html.substring(tdStart[3], tdEnd[3]+5); // OWASP Risk
                String descContent = html.substring(tdStart[4]+4, tdEnd[4]);
                String cleanedDesc = stripRiskMarker(descContent);
                String td5 = html.substring(tdStart[5], tdEnd[5]+5); // details

                String newRowInner = td0 + td2 + td3 + "<td>"+escape(cleanedDesc.isEmpty()? "" : "Likelihood, Impact, Score")+"</td>";
                // Replace placeholder with real metrics and description
                newRowInner = td0 + td2 + td3 + "<td>"+escape(metrics)+"</td>" + "<td>"+escape(cleanedDesc)+"</td>" + td5;

                // Replace the old tds block [td0..td5]
                String before = html.substring(0, tdStart[0]);
                String after = html.substring(tdEnd[5]+5);
                html = before + newRowInner + after;

                searchPos = rowStart + newRowInner.length();
                issueIndex++;
            }

            // 5) Normalize headings and labels regardless of source encoding
            html = replaceTagContent(html, "h1", "Отчет API Defender", 1);
            html = replaceTitle(html, "Отчет API Defender");

            // Rebuild the first info paragraph (target/preset/duration)
            int h1 = html.indexOf("</h1>");
            if (h1 >= 0) {
                int pStart = html.indexOf("<p>", h1);
                int pEnd = pStart >= 0 ? html.indexOf("</p>", pStart) : -1;
                if (pStart >= 0 && pEnd > pStart) {
                    String info = "<p><b>Цель:</b> "+escape(strOrEmpty(model.meta.target))+
                            "<br/><b>Профиль:</b> "+escape(strOrEmpty(model.meta.preset))+
                            "<br/><b>Длительность:</b> "+model.meta.durationMs+" мс</p>";
                    html = html.substring(0, pStart) + info + html.substring(pEnd+4);
                }
            }

            // Rename section headings by order
            html = replaceNthH2(html, 1, "Итоги");
            html = replaceNthH2(html, 2, "Несоответствия контракту");
            html = replaceNthH2(html, 3, "Неописанные эндпоинты");
            html = replaceNthH2(html, 4, "Уязвимости");

            // Fix headers for contract mismatches table (after 2nd h2)
            html = replaceTableHeaderAfterH2(html, 2, "<table><tr><th>Метод</th><th>Путь</th><th>Описание</th></tr>");
            // Fix headers for undocumented table (after 3rd h2)
            html = replaceTableHeaderAfterH2(html, 3, "<table><tr><th>Метод</th><th>Путь</th><th>Статус</th></tr>");

            // Normalize details labels inside <details>
            html = html.replaceAll("<summary>.*?</summary>", "<summary>Трейс</summary>");
            // Replace first bold in details block to 'Запрос', second to 'Ответ'
            html = html.replaceAll("(<details>[\\s\\S]*?<b>)([^<]{0,40})(</b><pre>)", "$1Запрос$3");
            html = html.replaceAll("(<pre>[\\s\\S]*?</pre><b>)([^<]{0,40})(</b><pre>)", "$1Ответ$3");
            html = html.replaceAll("Ссылка:\s*[:]?", "Ссылка:");
        } catch (Exception ignored) {}
        return html;
    }

    private String toCls(String severity){
        if (severity==null) return "low";
        String s = severity.toLowerCase();
        if (s.contains("critical")) return "critical";
        if (s.contains("high")) return "high";
        if (s.contains("medium")) return "medium";
        return "low";
    }

    private String escape(String s){
        if (s==null) return "";
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;");
    }

    private String strOrEmpty(String s){ return s==null? "" : s; }

    private String fmt(double v){
        return String.format(java.util.Locale.US, "%.1f", v);
    }

    private String stripRiskMarker(String s){
        if (s == null) return "";
        int i = s.indexOf("[OWASP Risk:");
        if (i >= 0) {
            int j = s.indexOf(']', i);
            if (j > i) {
                return s.substring(0, i).trim() + s.substring(j+1).trim();
            }
        }
        return s;
    }

    // Helpers for robust HTML surgery
    private String replaceTagContent(String html, String tag, String newText, int nth){
        int pos = 0; int count = 0;
        while (true){
            int open = html.indexOf("<"+tag+">", pos);
            if (open < 0) break; count++;
            int close = html.indexOf("</"+tag+">", open);
            if (close < 0) break;
            if (count == nth){
                return html.substring(0, open) + "<"+tag+">"+ newText +"</"+tag+">" + html.substring(close+("</"+tag+">").length());
            }
            pos = close + 1;
        }
        return html;
    }

    private String replaceTitle(String html, String title){
        int t1 = html.indexOf("<title>");
        int t2 = t1 >= 0 ? html.indexOf("</title>", t1) : -1;
        if (t1 >= 0 && t2 > t1) return html.substring(0, t1) + "<title>"+title+"</title>" + html.substring(t2+8);
        return html;
    }

    private String replaceNthH2(String html, int nth, String text){
        int pos = 0; int count = 0;
        while (true){
            int open = html.indexOf("<h2>", pos);
            if (open < 0) break; count++;
            int close = html.indexOf("</h2>", open);
            if (close < 0) break;
            if (count == nth){
                return html.substring(0, open) + "<h2>"+text+"</h2>" + html.substring(close+5);
            }
            pos = close + 1;
        }
        return html;
    }

    private String replaceTableHeaderAfterH2(String html, int nthH2, String newHeader){
        int pos = 0; int count = 0;
        while (true){
            int open = html.indexOf("<h2>", pos);
            if (open < 0) return html; count++;
            int close = html.indexOf("</h2>", open);
            if (close < 0) return html;
            if (count == nthH2){
                int tbl = html.indexOf("<table><tr><th", close);
                if (tbl < 0) return html;
                int trEnd = html.indexOf("</tr>", tbl);
                if (trEnd < 0) return html;
                return html.substring(0, tbl) + newHeader + html.substring(trEnd+5);
            }
            pos = close + 1;
        }
    }
}

