package ru.apidefender.core.openapi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class OpenApiLoader {
    public static class LoadedSpec {
        public final JsonNode root; // raw tree
        public final String version;
        public final String firstServerUrl;
        public LoadedSpec(JsonNode root, String version, String firstServerUrl) {
            this.root = root; this.version = version; this.firstServerUrl = firstServerUrl;
        }
    }

    public LoadedSpec load(Path path) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        String content = new String(bytes);
        ObjectMapper mapper = content.trim().startsWith("{")? new ObjectMapper(): new ObjectMapper(new YAMLFactory());
        JsonNode root = mapper.readTree(content);
        String version = root.path("openapi").asText("3.x");
        String server = null;
        if (root.has("servers") && root.get("servers").isArray() && root.get("servers").size()>0) {
            server = root.get("servers").get(0).path("url").asText(null);
        }
        return new LoadedSpec(root, version, server);
    }
}

