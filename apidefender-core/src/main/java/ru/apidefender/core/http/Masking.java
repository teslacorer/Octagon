package ru.apidefender.core.http;

import java.util.Locale;

public class Masking {
    private static final String JWT_REGEX = "(?i)(Bearer\\s+)?([A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+)";

    public static String maskSecrets(String s) {
        if (s == null) return null;
        return s.replaceAll(JWT_REGEX, "***");
    }

    public static String maskHeader(String name, String value){
        if (value == null) return null;
        String n = name == null? "" : name.toLowerCase(Locale.ROOT);
        if (n.equals("authorization") || n.equals("cookie") || n.equals("set-cookie") || n.contains("token") || n.contains("jwt")) return "***";
        return maskSecrets(value);
    }
}
