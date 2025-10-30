package ru.apidefender.core;

import java.nio.file.Path;
import java.time.Duration;

public class Config {
    public enum Preset { FAST, FULL, AGGRESSIVE }
    public enum LogLevel { INFO, DEBUG }

    private Path openapiPath;
    private String baseUrlOverride;
    private Path tokenFile;
    private Preset preset = Preset.FULL;
    private Duration timeout = Duration.ofMinutes(5);
    private Integer concurrency; // null = auto
    private Path reportHtml;
    private Path reportPdf;
    private Path reportJson;
    private Path tracesDir;
    private LogLevel logLevel = LogLevel.INFO;
    private boolean discoverUndocumented = true;
    private boolean strictContract = true;
    private boolean maskSecrets = true;

    public Path getOpenapiPath() { return openapiPath; }
    public void setOpenapiPath(Path openapiPath) { this.openapiPath = openapiPath; }

    public String getBaseUrlOverride() { return baseUrlOverride; }
    public void setBaseUrlOverride(String baseUrlOverride) { this.baseUrlOverride = baseUrlOverride; }

    public Path getTokenFile() { return tokenFile; }
    public void setTokenFile(Path tokenFile) { this.tokenFile = tokenFile; }

    public Preset getPreset() { return preset; }
    public void setPreset(Preset preset) { this.preset = preset; }

    public Duration getTimeout() { return timeout; }
    public void setTimeout(Duration timeout) { this.timeout = timeout; }

    public Integer getConcurrency() { return concurrency; }
    public void setConcurrency(Integer concurrency) { this.concurrency = concurrency; }

    public Path getReportHtml() { return reportHtml; }
    public void setReportHtml(Path reportHtml) { this.reportHtml = reportHtml; }

    public Path getReportPdf() { return reportPdf; }
    public void setReportPdf(Path reportPdf) { this.reportPdf = reportPdf; }

    public Path getReportJson() { return reportJson; }
    public void setReportJson(Path reportJson) { this.reportJson = reportJson; }

    public Path getTracesDir() { return tracesDir; }
    public void setTracesDir(Path tracesDir) { this.tracesDir = tracesDir; }

    public LogLevel getLogLevel() { return logLevel; }
    public void setLogLevel(LogLevel logLevel) { this.logLevel = logLevel; }

    public boolean isDiscoverUndocumented() { return discoverUndocumented; }
    public void setDiscoverUndocumented(boolean discoverUndocumented) { this.discoverUndocumented = discoverUndocumented; }

    public boolean isStrictContract() { return strictContract; }
    public void setStrictContract(boolean strictContract) { this.strictContract = strictContract; }

    public boolean isMaskSecrets() { return maskSecrets; }
    public void setMaskSecrets(boolean maskSecrets) { this.maskSecrets = maskSecrets; }
}

