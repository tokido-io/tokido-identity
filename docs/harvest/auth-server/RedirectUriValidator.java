package io.tokido.auth.service;

import jakarta.enterprise.context.ApplicationScoped;

import java.net.URI;
import java.util.List;
import java.util.regex.Pattern;

@ApplicationScoped
public class RedirectUriValidator {
    private static final Pattern URI_PATTERN = Pattern.compile("^(https?)://([^/]+)(/.*)?$");

    public boolean isAllowed(List<String> allowedRedirectUris, String redirectUri) {
        if (allowedRedirectUris == null || redirectUri == null || redirectUri.isBlank()) {
            return false;
        }
        return allowedRedirectUris.stream().anyMatch(pattern -> matches(pattern, redirectUri));
    }

    private boolean matches(String pattern, String candidate) {
        if (pattern == null || pattern.isBlank()) {
            return false;
        }
        if (!pattern.contains("*")) {
            return pattern.equals(candidate);
        }

        var patternMatch = URI_PATTERN.matcher(pattern);
        if (!patternMatch.matches()) {
            return false;
        }

        URI candidateUri = URI.create(candidate);

        String patternScheme = patternMatch.group(1);
        String patternHost = patternMatch.group(2);
        String patternPath = patternMatch.group(3);

        if (!safeEquals(patternScheme, candidateUri.getScheme())) {
            return false;
        }
        if (!hostMatches(patternHost, candidateUri.getHost())) {
            return false;
        }
        return pathMatches(patternPath, candidateUri.getPath());
    }

    private boolean hostMatches(String patternHost, String candidateHost) {
        if (patternHost == null || candidateHost == null) {
            return false;
        }
        if (!patternHost.contains("*")) {
            return patternHost.equals(candidateHost);
        }
        if (!patternHost.startsWith("*.")) {
            return false;
        }

        String suffix = patternHost.substring(2);
        String[] suffixParts = suffix.split("\\.");
        if (suffixParts.length < 3) {
            return false;
        }
        if (!candidateHost.endsWith("." + suffix)) {
            return false;
        }

        String prefix = candidateHost.substring(0, candidateHost.length() - suffix.length() - 1);
        return !prefix.isBlank() && !prefix.contains("*");
    }

    private boolean pathMatches(String patternPath, String candidatePath) {
        String normalizedPattern = patternPath == null || patternPath.isBlank() ? "/" : patternPath;
        String normalizedCandidate = candidatePath == null || candidatePath.isBlank() ? "/" : candidatePath;
        if (!normalizedPattern.contains("*")) {
            return normalizedPattern.equals(normalizedCandidate);
        }
        String regex = normalizedPattern
            .replace(".", "\\.")
            .replace("*", ".*");
        return normalizedCandidate.matches(regex);
    }

    private boolean safeEquals(String left, String right) {
        return left != null && left.equals(right);
    }
}
