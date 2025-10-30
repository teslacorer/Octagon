package ru.apidefender.core.http;

import okhttp3.*;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

public class HttpClient {
    private final OkHttpClient client;
    private final String token;
    private final boolean maskSecrets;

    public HttpClient(Duration timeout, String token, boolean maskSecrets) {
        this.client = new OkHttpClient.Builder()
                .callTimeout(timeout)
                .build();
        this.token = token;
        this.maskSecrets = maskSecrets;
    }

    public Response request(String method, String url, Map<String, String> headers, RequestBody body) throws IOException {
        Request.Builder b = new Request.Builder().url(url);
        if (token != null && !token.isBlank()) b.header("Authorization", "Bearer " + token);
        if (headers != null) headers.forEach(b::header);
        switch (method.toUpperCase()) {
            case "GET" -> b.get();
            case "POST" -> b.post(body != null ? body : RequestBody.create(new byte[0]));
            case "PUT" -> b.put(body != null ? body : RequestBody.create(new byte[0]));
            case "PATCH" -> b.patch(body != null ? body : RequestBody.create(new byte[0]));
            case "DELETE" -> b.delete(body);
            case "HEAD" -> b.head();
            default -> throw new IllegalArgumentException("Неизвестный метод: " + method);
        }
        return client.newCall(b.build()).execute();
    }

    // Overload that allows duplicate headers by using addHeader
    public Response requestWithMultiHeaders(String method, String url, Map<String, java.util.List<String>> headers, RequestBody body) throws IOException {
        Request.Builder b = new Request.Builder().url(url);
        if (token != null && !token.isBlank()) b.header("Authorization", "Bearer " + token);
        if (headers != null) headers.forEach((k, vs) -> {
            if (vs != null) for (String v : vs) b.addHeader(k, v);
        });
        switch (method.toUpperCase()) {
            case "GET" -> b.get();
            case "POST" -> b.post(body != null ? body : RequestBody.create(new byte[0]));
            case "PUT" -> b.put(body != null ? body : RequestBody.create(new byte[0]));
            case "PATCH" -> b.patch(body != null ? body : RequestBody.create(new byte[0]));
            case "DELETE" -> b.delete(body);
            case "HEAD" -> b.head();
            default -> throw new IllegalArgumentException("Неподдерживаемый метод: " + method);
        }
        return client.newCall(b.build()).execute();
    }

    public static String dumpResponse(Response resp, boolean mask) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(resp.request().method()).append(" ").append(resp.request().url()).append("\n");
        for (String h : resp.request().headers().names()) {
            String v = resp.request().header(h);
            sb.append(h).append(": ").append(mask? Masking.maskSecrets(v): v).append("\n");
        }
        sb.append("--\n");
        sb.append(resp.code()).append(" ").append(resp.message()).append("\n");
        for (String h : resp.headers().names()) {
            String v = resp.header(h);
            sb.append(h).append(": ").append(mask? Masking.maskSecrets(v): v).append("\n");
        }
        String body = resp.peekBody(Long.MAX_VALUE).string();
        sb.append("\n").append(mask? Masking.maskSecrets(body): body);
        return sb.toString();
    }
}
