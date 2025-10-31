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
        Files.writeString(path, html, StandardCharsets.UTF_8);
    }

    public void writePdf(ReportModel model, Path path) throws Exception {
        if (path.getParent() != null) Files.createDirectories(path.getParent());
        String html = HtmlTemplates.render(model);
        try (OutputStream os = new FileOutputStream(path.toFile())) {
            PdfRendererBuilder builder = new PdfRendererBuilder();
            builder.useFastMode();
            builder.withHtmlContent(html, null);
            builder.toStream(os);
            builder.run();
        }
    }
}
