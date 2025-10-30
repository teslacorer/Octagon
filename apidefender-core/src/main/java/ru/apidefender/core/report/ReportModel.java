package ru.apidefender.core.report;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.*;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class ReportModel {
    public static class Meta {
        public String startedAt;
        public String finishedAt;
        public long durationMs;
        public String preset;
        public String target;
        public String openapiVersion;
        public int endpointsScanned;
        public String tracesDir;
    }
    public static class ContractMismatch {
        public String endpoint;
        public String method;
        public String issue;
        public String evidence;
        public String traceRef;
    }
    public static class Undocumented {
        public String path;
        public String method;
        public int status;
        public String evidence;
        public String traceRef;
    }
    public static class SecurityIssue {
        public String id;
        public String category;
        public String severity;
        public String endpoint;
        public String method;
        public String description;
        public String evidence;
        public String impact;
        public String recommendation;
        public String traceRef;
    }
    public static class Telemetry {
        public int requestsTotal;
        public double avgLatencyMs;
        public double contractMismatchRate;
        public Map<String,Integer> vulnCounts = new HashMap<>();
        public Map<String,Integer> scannerAttempts = new HashMap<>();
        public Map<String,Long> scannerDurMs = new HashMap<>();
        public Map<String,Object> presetParams = new HashMap<>();
    }

    public Meta meta = new Meta();
    public static class Contract {
        public List<ContractMismatch> mismatches = new ArrayList<>();
        public List<Undocumented> undocumented = new ArrayList<>();
    }
    public Contract contract = new Contract();
    public List<SecurityIssue> security = new ArrayList<>();
    public Telemetry telemetry = new Telemetry();
}
