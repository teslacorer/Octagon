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
        mapper.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), model);
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

