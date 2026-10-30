package ai.lmctl.azuresim;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.net.URI;
import io.vertx.core.http.HttpServerRequest;
import jakarta.ws.rs.core.Context;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

/** Opt-in boundary overlay. Upstream's protocol handlers are unchanged. */
@ApplicationScoped
public class StorageAuth {
    private static volatile Config config;
    private record Rule(boolean deny, List<String> actions, List<String> resources, List<String> principals) {}
    private record Config(Map<String, byte[]> accounts, Map<String, String> tokens, boolean policyPresent, List<Rule> rules) {}
    private record Target(String account, String service, String path, String action) {
        String resource() { return "/" + account + "/" + service + path; }
    }

    static void configure(String mode, String file) throws Exception {
        if (!Set.of("open", "enforce").contains(mode)) throw new IllegalArgumentException();
        if (mode.equals("open")) {
            if (file != null) throw new IllegalArgumentException();
            config = null;
            return;
        }
        if (file == null || Files.size(Path.of(file)) > 1024 * 1024) throw new IllegalArgumentException();
        JsonNode root = new ObjectMapper().enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(Files.readString(Path.of(file)));
        keys(root, Set.of("accounts", "tokens", "Statement"));
        Map<String, byte[]> accounts = new HashMap<>();
        if (root.has("accounts")) {
            JsonNode node = root.get("accounts");
            if (!node.isObject()) throw new IllegalArgumentException();
            for (var it = node.fields(); it.hasNext();) {
                var pair = it.next();
                if (!pair.getKey().matches("[a-z0-9]{3,24}") || !pair.getValue().isTextual()) throw new IllegalArgumentException();
                byte[] key = Base64.getDecoder().decode(pair.getValue().asText());
                if (key.length < 16) throw new IllegalArgumentException();
                accounts.put(pair.getKey(), key);
            }
        }
        Map<String, String> tokens = new HashMap<>();
        if (root.has("tokens")) {
            JsonNode node = root.get("tokens");
            if (!node.isObject()) throw new IllegalArgumentException();
            for (var it = node.fields(); it.hasNext();) {
                var pair = it.next();
                if (!pair.getKey().matches("[A-Za-z0-9._~+/-]+=*") || !pair.getValue().isTextual()
                        || pair.getValue().asText().isBlank()) throw new IllegalArgumentException();
                tokens.put(pair.getKey(), pair.getValue().asText());
            }
        }
        if (tokens.isEmpty() && accounts.isEmpty()) throw new IllegalArgumentException();
        List<Rule> rules = new ArrayList<>();
        if (root.has("Statement")) {
            if (!root.get("Statement").isArray()) throw new IllegalArgumentException();
            for (JsonNode node : root.get("Statement")) {
                keys(node, Set.of("Effect", "Action", "ActionGlob", "ResourceGlob", "Principal"));
                String effect = node.path("Effect").asText();
                if (!Set.of("Allow", "Deny").contains(effect) || node.has("Action") == node.has("ActionGlob")) throw new IllegalArgumentException();
                rules.add(new Rule(effect.equals("Deny"), strings(node.get(node.has("Action") ? "Action" : "ActionGlob")),
                    strings(node.get("ResourceGlob")), node.has("Principal") ? strings(node.get("Principal")) : List.of("*")));
            }
        }
        config = new Config(Map.copyOf(accounts), Map.copyOf(tokens), root.has("Statement"), List.copyOf(rules));
    }

    private static void keys(JsonNode node, Set<String> allowed) {
        if (node == null || !node.isObject()) throw new IllegalArgumentException();
        node.fieldNames().forEachRemaining(key -> { if (!allowed.contains(key)) throw new IllegalArgumentException(); });
    }
    private static List<String> strings(JsonNode node) {
        if (node == null) throw new IllegalArgumentException();
        if (node.isTextual() && !node.asText().isBlank()) return List.of(node.asText());
        if (!node.isArray() || node.isEmpty()) throw new IllegalArgumentException();
        List<String> values = new ArrayList<>();
        for (JsonNode v : node) {
            if (!v.isTextual() || v.asText().isBlank()) throw new IllegalArgumentException();
            values.add(v.asText());
        }
        return values;
    }

    @ServerRequestFilter(preMatching = true, priority = 1000)
    public Response enforce(ContainerRequestContext request, @Context HttpServerRequest wireRequest) {
        Config c = config;
        if (c == null) return null;
        try {
            Map<String, String> headers = new TreeMap<>();
            for (var entry : request.getHeaders().entrySet()) {
                String key = entry.getKey().toLowerCase(Locale.ROOT);
                if (entry.getValue().size() != 1 || headers.put(key, entry.getValue().getFirst()) != null)
                    return error("AuthenticationFailed");
            }
            URI wireUri = URI.create(wireRequest.uri());
            Target target = target(request, headers, wireUri);
            String authorization = headers.getOrDefault("authorization", "");
            String principal;
            if (authorization.startsWith("Bearer ")) {
                principal = null;
                byte[] offered = authorization.substring(7).getBytes(StandardCharsets.UTF_8);
                for (var token : c.tokens.entrySet()) {
                    if (MessageDigest.isEqual(offered, token.getKey().getBytes(StandardCharsets.UTF_8))) principal = token.getValue();
                }
                if (principal == null) return error("AuthenticationFailed");
            } else if (authorization.startsWith("SharedKey ") && target != null) {
                String[] credentials = authorization.substring(10).split(":", -1);
                if (credentials.length != 2 || !credentials[0].equals(target.account)) return error("AuthenticationFailed");
                byte[] key = c.accounts.get(credentials[0]);
                if (key == null) return error("AuthenticationFailed");
                String date = headers.getOrDefault("x-ms-date", headers.getOrDefault("date", ""));
                Instant stamp = ZonedDateTime.parse(date, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
                if (Math.abs(Instant.now().getEpochSecond() - stamp.getEpochSecond()) > 900) return error("AuthenticationFailed");
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(key, "HmacSHA256"));
                byte[] expected = mac.doFinal(canonical(request, headers, target.account, wireUri).getBytes(StandardCharsets.UTF_8));
                if (!MessageDigest.isEqual(expected, Base64.getDecoder().decode(credentials[1]))) return error("AuthenticationFailed");
                principal = credentials[0];
            } else return error("AuthenticationFailed");
            // Fail closed for all services/operations outside the documented storage subset.
            if (target == null || target.action == null) return error("AuthorizationPermissionMismatch");
            boolean allowed = !c.policyPresent;
            for (Rule rule : c.rules) {
                if (matches(rule.actions.stream().map(v -> v.toLowerCase(Locale.ROOT)).toList(), target.action.toLowerCase(Locale.ROOT)) && matches(rule.resources, target.resource()) && matches(rule.principals, principal)) {
                    if (rule.deny) return error("AuthorizationPermissionMismatch");
                    allowed = true;
                }
            }
            return allowed ? null : error("AuthorizationPermissionMismatch");
        } catch (Exception ignored) {
            // Never include credential material, signatures, config or exception messages.
            return error("AuthenticationFailed");
        }
    }

    private static Response error(String code) {
        String message = code.equals("AuthenticationFailed") ? "Server failed to authenticate the request."
            : "This request is not authorized to perform this operation using this permission.";
        return Response.status(403).type("application/xml").header("x-ms-error-code", code)
            .header("x-ms-request-id", UUID.randomUUID().toString())
            .entity("<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>" + code + "</Code><Message>" + message + "</Message></Error>").build();
    }

    private static boolean matches(List<String> globs, String value) {
        for (String glob : globs) {
            StringBuilder regex = new StringBuilder("\\A");
            for (char ch : glob.toCharArray()) regex.append(ch == '*' ? ".*" : ch == '?' ? "." : Pattern.quote(String.valueOf(ch)));
            if (Pattern.compile(regex + "\\z", Pattern.DOTALL).matcher(value).matches()) return true;
        }
        return false;
    }

    private static Map<String, List<String>> query(String raw) {
        Map<String, List<String>> values = new TreeMap<>();
        if (raw != null && !raw.isEmpty()) for (String part : raw.split("&")) {
            String[] pair = part.split("=", 2);
            String key = URLDecoder.decode(pair[0], StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
            values.computeIfAbsent(key, ignored -> new ArrayList<>()).add(URLDecoder.decode(pair.length == 2 ? pair[1] : "", StandardCharsets.UTF_8));
        }
        return values;
    }

    private static String canonical(ContainerRequestContext r, Map<String, String> h, String account, URI wireUri) {
        StringBuilder out = new StringBuilder(r.getMethod()).append('\n');
        for (String name : List.of("content-encoding", "content-language", "content-length", "content-md5", "content-type", "date",
                "if-modified-since", "if-match", "if-none-match", "if-unmodified-since", "range")) {
            String value = h.getOrDefault(name, "");
            if (name.equals("date") && h.containsKey("x-ms-date")) value = "";
            if (name.equals("content-length") && value.equals("0") && h.getOrDefault("x-ms-version", "9999").compareTo("2014-02-14") > 0) value = "";
            out.append(value).append('\n');
        }
        h.forEach((key, value) -> {
            if (key.startsWith("x-ms-") && (!value.isEmpty() || h.getOrDefault("x-ms-version", "9999").compareTo("2016-05-31") >= 0))
                out.append(key).append(':').append(whitespace(value)).append('\n');
        });
        out.append('/').append(account).append(wireUri.getRawPath());
        query(wireUri.getRawQuery()).forEach((key, values) -> {
            Collections.sort(values);
            out.append('\n').append(key).append(':').append(String.join(",", values));
        });
        return out.toString();
    }

    private static String whitespace(String value) {
        StringBuilder out = new StringBuilder();
        boolean quoted = false, space = false, escaped = false;
        for (char ch : value.trim().toCharArray()) {
            if (!quoted && Character.isWhitespace(ch)) { space = true; continue; }
            if (space && !out.isEmpty()) out.append(' ');
            space = false;
            out.append(ch);
            if (ch == '"' && !escaped) quoted = !quoted;
            escaped = ch == '\\' && !escaped;
        }
        return out.toString();
    }

    private static Target target(ContainerRequestContext r, Map<String, String> headers, URI wireUri) {
        String raw = wireUri.getRawPath();
        String path = wireUri.getPath();
        if (raw.toLowerCase(Locale.ROOT).matches(".*%(2f|5c|25).*") || path.contains("\\") || path.contains(";") || path.contains("//") || (path.length() > 1 && path.endsWith("/"))
                || Arrays.asList(path.split("/", -1)).stream().anyMatch(v -> v.equals(".") || v.equals(".."))) return null;
        String host = headers.getOrDefault("host", "").split(":")[0].toLowerCase(Locale.ROOT);
        String account, service;
        if (host.matches("[a-z0-9]{3,24}\\.(blob|queue)\\.core\\.windows\\.net")) {
            String[] bits = host.split("\\."); account = bits[0]; service = bits[1];
        } else {
            if (!(host.equals("127.0.0.1") || host.equals("localhost"))) return null;
            String[] parts = path.split("/", 3);
            if (parts.length < 2) return null;
            service = parts[1].endsWith("-queue") ? "queue" : "blob";
            account = service.equals("queue") ? parts[1].substring(0, parts[1].length() - 6) : parts[1];
            path = parts.length == 3 ? "/" + parts[2] : "/";
        }
        if (!account.matches("[a-z0-9]{3,24}")) return null;
        Map<String, List<String>> q = query(wireUri.getRawQuery());
        String comp = q.getOrDefault("comp", List.of("")).getFirst();
        String method = r.getMethod();
        String action = null;
        int segments = (int) Arrays.stream(path.split("/")).filter(v -> !v.isEmpty()).count();
        if (service.equals("blob")) {
            boolean container = q.getOrDefault("restype", List.of("")).equals(List.of("container"));
            String prefix = "Microsoft.Storage/storageAccounts/blobServices/containers";
            if (segments == 0 && method.equals("GET") && comp.equals("list")) action = prefix + "/read";
            else if (container && segments == 1 && (comp.isEmpty() || comp.equals("list") || comp.equals("metadata")))
                action = prefix + (comp.equals("list") ? (method.equals("GET") ? "/blobs/read" : "null") : suffix(method));
            else if (!container && segments >= 2 && (comp.isEmpty() || Set.of("block", "blocklist", "metadata").contains(comp)))
                action = prefix + "/blobs" + suffix(method);
        } else {
            String prefix = "Microsoft.Storage/storageAccounts/queueServices/queues";
            if (segments == 0 && method.equals("GET") && comp.equals("list")) action = prefix + "/read";
            else if (segments == 1 && (comp.isEmpty() || comp.equals("metadata"))) action = prefix + suffix(method);
            else if (path.matches("/[^/]+/messages(?:/[^/]+)?") && comp.isEmpty()) {
                String operation = switch (method) {
                    case "POST" -> "/add/action";
                    case "GET" -> q.getOrDefault("peekonly", List.of("false")).equals(List.of("true")) ? "/read" : "/process/action";
                    case "DELETE" -> "/delete";
                    case "PUT" -> "/write";
                    default -> null;
                };
                if (operation != null) action = prefix + "/messages" + operation;
            }
        }
        if (action != null && action.endsWith("null")) action = null;
        return new Target(account, service, path, action);
    }
    private static String suffix(String method) {
        return switch (method) { case "GET", "HEAD" -> "/read"; case "PUT" -> "/write"; case "DELETE" -> "/delete"; default -> null; };
    }
}
