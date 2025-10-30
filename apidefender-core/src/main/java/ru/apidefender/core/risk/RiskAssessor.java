package ru.apidefender.core.risk;

import ru.apidefender.core.report.ReportModel;

public class RiskAssessor {
    public static class Risk {
        public final double likelihood; // 0..9
        public final double impact;     // 0..9
        public final double score;      // avg(l,i)
        public final String rating;     // Low/Medium/High/Critical
        public Risk(double l, double i, double s, String r){ this.likelihood=l; this.impact=i; this.score=s; this.rating=r; }
    }

    public static Risk compute(ReportModel.SecurityIssue si) {
        String cat = si.category != null? si.category : "";
        String desc = si.description != null? si.description.toLowerCase() : "";
        String evid = si.evidence != null? si.evidence.toLowerCase() : "";
        String endpoint = si.endpoint != null? si.endpoint.toLowerCase() : "";

        double l = 3.0, i = 3.0;

        // Likelihood heuristics by category and confirmation cues
        switch (cat) {
            case "Injection" -> {
                l = desc.contains("boolean-blind") || desc.contains("union-extract") ? 8.0 : 6.0;
                i = 8.0; // technical impact high
            }
            case "IDOR", "BOLA" -> {
                l = 8.0; // easy to repeat
                i = 7.0; // confidentiality
            }
            case "WeakAuth" -> {
                boolean invalidAccepted = desc.contains("invalid") || evid.contains("authorization: bearer invalid");
                l = invalidAccepted ? 8.0 : 6.0;
                i = invalidAccepted ? 8.0 : 6.0;
            }
            case "ExcessiveData" -> {
                boolean pii = desc.contains("pii") || evid.contains("email") || evid.contains("phone") || evid.contains("card");
                l = 6.0;
                i = pii ? 7.0 : 5.0;
            }
            case "RateLimit" -> {
                boolean errors = evid.contains("429") || evid.contains("5xx") || desc.contains("ошиб") || desc.contains("error");
                l = 5.0;
                i = errors ? 6.0 : 4.0;
            }
            case "SecurityHeaders", "CORS", "MassAssignment", "VerboseErrors" -> {
                l = 4.0; i = 4.0;
            }
            default -> { l = 4.0; i = 4.0; }
        }

        // Endpoint sensitivity boosters
        if (endpoint.contains("/admin") || endpoint.contains("/internal") || endpoint.contains("/manage") || endpoint.contains("/transactions") || endpoint.contains("/accounts")) {
            i = Math.min(9.0, i + 1.0);
        }

        double score = (l + i) / 2.0;
        String rating = toRating(score);
        return new Risk(l, i, score, rating);
    }

    public static String toRating(double score){
        if (score >= 8.0) return "Critical";
        if (score >= 6.0) return "High";
        if (score >= 3.0) return "Medium";
        return "Low";
    }
}

