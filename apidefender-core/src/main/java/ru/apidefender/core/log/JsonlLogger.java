package ru.apidefender.core.log;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

public class JsonlLogger {
    private final ObjectMapper mapper = new ObjectMapper();
    private final boolean debug;
    private final Path logFile; // optional separate JSONL file

    public JsonlLogger(boolean debug) { this(debug, null); }

    public JsonlLogger(boolean debug, Path logFile) {
        this.debug = debug;
        this.logFile = logFile;
    }

    public void info(String message) { log("info", message, null); }
    public void debug(String message) { if (debug) log("debug", message, null); }
    public void error(String message, Throwable t) { log("error", message, t); }

    private synchronized void log(String level, String message, Throwable t) {
        try {
            ObjectNode node = mapper.createObjectNode();
            node.put("ts", Instant.now().toString());
            node.put("level", level);
            node.put("msg", message);
            if (t != null) node.put("error", t.toString());
            String line = mapper.writeValueAsString(node);
            System.out.println(line);
            if (logFile != null) {
                try {
                    Files.createDirectories(logFile.getParent());
                } catch (Exception ignored) {}
                Files.writeString(logFile, line + System.lineSeparator(), StandardCharsets.UTF_8,
                        Files.exists(logFile) ? java.nio.file.StandardOpenOption.APPEND : java.nio.file.StandardOpenOption.CREATE);
            }
        } catch (IOException ignored) { }
    }
}
