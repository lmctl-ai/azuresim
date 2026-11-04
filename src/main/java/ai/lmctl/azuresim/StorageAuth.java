package ai.lmctl.azuresim;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.net.URI;
import io.vertx.core.http.HttpServerRequest;
import jakarta.ws.rs.core.Context;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
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
    private record Target(String account, String service, String path, String unwrappedPath, String action) {
        String resource() { return "/" + account + "/" + service + path; }
        String unwrappedResource() { return "/" + account + "/" + service + unwrappedPath; }
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
            String targetAccount = target != null ? target.account : resolveAccount(headers, wireUri);
            String authorization = headers.getOrDefault("authorization", "");
            String principal;
            if (authorization.startsWith("Bearer ")) {
                principal = null;
                byte[] offered = authorization.substring(7).getBytes(StandardCharsets.UTF_8);
                for (var token : c.tokens.entrySet()) {
                    if (MessageDigest.isEqual(offered, token.getKey().getBytes(StandardCharsets.UTF_8))) principal = token.getValue();
                }
                if (principal == null) return error("AuthenticationFailed");
            } else if (authorization.startsWith("SharedKey ") && targetAccount != null) {
                String[] credentials = authorization.substring(10).split(":", -1);
                if (credentials.length != 2 || !credentials[0].equals(targetAccount)) return error("AuthenticationFailed");
                byte[] key = c.accounts.get(credentials[0]);
                if (key == null) return error("AuthenticationFailed");
                String date = headers.getOrDefault("x-ms-date", headers.getOrDefault("date", ""));
                Instant stamp = ZonedDateTime.parse(date, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
                if (Math.abs(Instant.now().getEpochSecond() - stamp.getEpochSecond()) > 900) return error("AuthenticationFailed");
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(key, "HmacSHA256"));
                byte[] expected = mac.doFinal(canonical(request, headers, targetAccount, wireUri).getBytes(StandardCharsets.UTF_8));
                if (!MessageDigest.isEqual(expected, Base64.getDecoder().decode(credentials[1]))) return error("AuthenticationFailed");
                principal = credentials[0];
            } else return error("AuthenticationFailed");
            // Fail closed for all services/operations outside the documented storage subset.
            if (target == null || target.action == null) return error("AuthorizationPermissionMismatch");
            boolean allowed = !c.policyPresent;
            for (Rule rule : c.rules) {
                if (matches(rule.actions.stream().map(v -> v.toLowerCase(Locale.ROOT)).toList(), target.action.toLowerCase(Locale.ROOT)) && matches(rule.principals, principal)) {
                    if (rule.deny && (matches(rule.resources, target.resource()) || matches(rule.resources, target.unwrappedResource()))) {
                        return error("AuthorizationPermissionMismatch");
                    }
                    if (!rule.deny && matches(rule.resources, target.resource())) {
                        allowed = true;
                    }
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
            .entity("""
                <?xml version="1.0" encoding="utf-8"?><Error><Code>%s</Code><Message>%s</Message></Error>
                """.formatted(ResponseTemplates.xml(code), ResponseTemplates.xml(message))).build();
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

    private static String resolveAccount(Map<String, String> headers, URI wireUri) {
        String host = headers.getOrDefault("host", "").split(":")[0].toLowerCase(Locale.ROOT);
        if (host.matches("[a-z0-9]{3,24}\\.(blob|queue)\\.core\\.windows\\.net")) {
            return host.split("\\.")[0];
        }
        if (!(host.equals("127.0.0.1") || host.equals("localhost"))) return null;
        String raw = wireUri.getRawPath();
        if (raw == null || !raw.startsWith("/")) return null;
        String[] parts = raw.split("/", 3);
        if (parts.length < 2) return null;
        String seg = parts[1].toLowerCase(Locale.ROOT).split("%2f|%5c|%252f|%255c", 2)[0];
        String acct = seg.endsWith("-queue") ? seg.substring(0, seg.length() - 6) : seg;
        return acct.matches("[a-z0-9]{3,24}") ? acct : null;
    }

    private static String decodeOnceStrict(String raw) {
        if (raw == null || !raw.startsWith("/")) return null;
        ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length());
        for (int i = 0; i < raw.length(); ) {
            char ch = raw.charAt(i);
            if (ch == '%') {
                if (i + 2 >= raw.length()) return null;
                int hi = Character.digit(raw.charAt(i + 1), 16);
                int lo = Character.digit(raw.charAt(i + 2), 16);
                if (hi < 0 || lo < 0) return null;
                out.write((hi << 4) | lo);
                i += 3;
            } else {
                int next = raw.indexOf('%', i);
                if (next < 0) next = raw.length();
                byte[] utf8 = raw.substring(i, next).getBytes(StandardCharsets.UTF_8);
                out.write(utf8, 0, utf8.length);
                i = next;
            }
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(out.toByteArray())).toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean hasInvalidPathShape(String p) {
        if (p == null || p.isEmpty() || !p.startsWith("/")) return true;
        if (p.contains("\\") || p.contains(";") || p.contains("//") || (p.length() > 1 && p.endsWith("/"))) return true;
        for (int i = 0; i < p.length(); i++) {
            char ch = p.charAt(i);
            if (ch < 0x20 || ch == 0x7f) return true;
        }
        return Arrays.asList(p.split("/", -1)).stream().anyMatch(v -> v.equals(".") || v.equals(".."));
    }

    private static int hexByteAt(String s, int i) {
        if (i + 2 >= s.length() || s.charAt(i) != '%') return -1;
        int hi = Character.digit(s.charAt(i + 1), 16);
        int lo = Character.digit(s.charAt(i + 2), 16);
        return (hi >= 0 && lo >= 0) ? ((hi << 4) | lo) : -1;
    }

    private static String decodeRelaxedOnce(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); ) {
            int b0 = hexByteAt(s, i);
            if (b0 < 0) {
                out.append(s.charAt(i++));
            } else if (b0 < 0x80) {
                out.append((char) b0);
                i += 3;
            } else {
                int b1 = hexByteAt(s, i + 3);
                if ((b0 & 0xE0) == 0xC0 && b1 >= 0x80 && b1 <= 0xBF) {
                    if (b0 < 0xC2) return null; // overlong 2-byte UTF-8
                    out.append(new String(new byte[]{(byte) b0, (byte) b1}, StandardCharsets.UTF_8));
                    i += 6;
                } else if ((b0 & 0xF0) == 0xE0 && b1 >= 0x80 && b1 <= 0xBF) {
                    int b2 = hexByteAt(s, i + 6);
                    if (b2 >= 0x80 && b2 <= 0xBF) {
                        if ((b0 == 0xE0 && b1 < 0xA0) || (b0 == 0xED && b1 >= 0xA0)) return null; // overlong or surrogate
                        out.append(new String(new byte[]{(byte) b0, (byte) b1, (byte) b2}, StandardCharsets.UTF_8));
                        i += 9;
                    } else {
                        out.append(s, i, i + 3);
                        i += 3;
                    }
                } else if ((b0 & 0xF8) == 0xF0 && b1 >= 0x80 && b1 <= 0xBF) {
                    int b2 = hexByteAt(s, i + 6), b3 = hexByteAt(s, i + 9);
                    if (b2 >= 0x80 && b2 <= 0xBF && b3 >= 0x80 && b3 <= 0xBF) {
                        if ((b0 == 0xF0 && b1 < 0x90) || b0 > 0xF4 || (b0 == 0xF4 && b1 >= 0x90)) return null;
                        out.append(new String(new byte[]{(byte) b0, (byte) b1, (byte) b2, (byte) b3}, StandardCharsets.UTF_8));
                        i += 12;
                    } else {
                        out.append(s, i, i + 3);
                        i += 3;
                    }
                } else {
                    out.append(s, i, i + 3);
                    i += 3;
                }
            }
        }
        return out.toString();
    }

    private static String unwrapAndValidate(String path) {
        String cur = path;
        for (int depth = 0; depth < 8 && cur.contains("%"); depth++) {
            if (cur.toLowerCase(Locale.ROOT).matches(".*%(2f|5c|00|3b).*")) return null;
            String next = decodeRelaxedOnce(cur);
            if (next == null || hasInvalidPathShape(next)) return null;
            if (next.equals(cur)) return cur;
            cur = next;
        }
        String extra = decodeRelaxedOnce(cur);
        if (extra == null || !extra.equals(cur)) return null;
        return cur;
    }

    private static boolean isEmulatorAdminPath(String trimmed) {
        return trimmed.equals("health") || trimmed.equals("ready")
            || trimmed.startsWith("_floci/") || trimmed.startsWith("_admin");
    }

    private static boolean isEntraPath(String trimmed) {
        return trimmed.contains("oauth2/v2.0/token") || trimmed.endsWith("oauth2/token")
            || trimmed.contains("oauth2/v2.0/authorize")
            || trimmed.endsWith("discovery/v2.0/keys")
            || trimmed.endsWith(".well-known/openid-configuration");
    }

    private static boolean isInterceptedBeforeStorageTerminal(String trimmed, String firstSegment,
            Map<String, String> headers, Map<String, List<String>> q) {
        if (trimmed.startsWith("metadata/identity/") || trimmed.equalsIgnoreCase("msi/token")
                || isEntraPath(trimmed) || trimmed.startsWith("metadata/endpoints") || trimmed.startsWith("v1.0/")
                || trimmed.startsWith("dataCollectionRules/") || trimmed.startsWith("v1/workspaces/")
                || trimmed.toLowerCase(Locale.ROOT).contains("/providers/microsoft.insights/diagnosticsettings")
                || trimmed.startsWith("emails:") || trimmed.startsWith("emails/") || trimmed.startsWith("emailMessages")
                || trimmed.startsWith("providers/") || trimmed.startsWith("subscriptions/") || trimmed.equals("subscriptions")
                || trimmed.startsWith("tenants/") || trimmed.equals("tenants")
                || trimmed.startsWith("$namespaceinfo") || trimmed.startsWith("$Resources")) {
            return true;
        }
        if (firstSegment.isEmpty() || Set.of("secrets", "certificates", "keys", "deletedsecrets",
                "deletedcertificates", "deletedkeys", "rng", "dbs", "colls", "docs", "pkranges",
                "offers", "sprocs", "triggers", "udfs").contains(firstSegment)) {
            return true;
        }
        String ct = headers.getOrDefault("content-type", "");
        String accept = headers.getOrDefault("accept", "");
        String ua = headers.getOrDefault("user-agent", "");
        if (ct.contains("application/atom+xml") || accept.contains("application/atom+xml")) {
            return true;
        }
        return ua.contains("azsdk-net-Messaging.ServiceBus/") && q.containsKey("api-version");
    }

    private static String resolvePathStyleStorageService(Map<String, String> headers,
            Map<String, List<String>> q, String resourcePath) {
        if (headers.containsKey("x-ms-blob-type")) {
            return "blob";
        }
        if (resourcePath.contains("/messages") || resourcePath.endsWith("/messages")) {
            return "queue";
        }
        List<String> restype = q.get("restype");
        if (restype != null && restype.contains("queue")) {
            return "queue";
        }
        if (headers.containsKey("x-ms-queue-message-count")) {
            return "queue";
        }
        return "blob";
    }

    private static Target target(ContainerRequestContext r, Map<String, String> headers, URI wireUri) {
        String raw = wireUri.getRawPath();
        if (raw == null || raw.isEmpty() || !raw.startsWith("/")) return null;
        if (raw.contains("\\") || raw.contains(";") || raw.contains("//") || raw.toLowerCase(Locale.ROOT).matches(".*%(2f|5c|00).*")) return null;
        String path = decodeOnceStrict(raw);
        if (path == null || !path.equals(wireUri.getPath()) || hasInvalidPathShape(path)) return null;
        if (r != null && r.getUriInfo() != null && r.getUriInfo().getPath() != null) {
            String routerPath = r.getUriInfo().getPath();
            if (!routerPath.startsWith("/")) routerPath = "/" + routerPath;
            if (!path.equals(routerPath)) return null;
        }
        String unwrapped = unwrapAndValidate(path);
        if (unwrapped == null) return null;
        if (isEmulatorAdminPath(path.substring(1)) || isEmulatorAdminPath(unwrapped.substring(1))) return null;
        String host = headers.getOrDefault("host", "").split(":")[0].toLowerCase(Locale.ROOT);
        if (r != null && r.getUriInfo() != null && r.getUriInfo().getRequestUri() != null) {
            String reqHost = r.getUriInfo().getRequestUri().getHost();
            if (reqHost != null && !reqHost.isBlank() && !reqHost.split(":")[0].toLowerCase(Locale.ROOT).equals(host)) {
                return null;
            }
        }
        Map<String, List<String>> q = query(wireUri.getRawQuery());
        for (String key : Set.of("comp", "restype", "peekonly", "action", "resource", "snapshot")) {
            if (q.containsKey(key)) {
                if (q.get(key).size() != 1) return null;
                if (r != null && r.getUriInfo() != null && r.getUriInfo().getQueryParameters() != null) {
                    List<String> routerVals = r.getUriInfo().getQueryParameters().get(key);
                    if (routerVals == null || !routerVals.equals(q.get(key))) return null;
                }
            }
        }
        String account, service, serviceUnwrappedPath;
        if (host.matches("[a-z0-9]{3,24}\\.(blob|queue)\\.core\\.windows\\.net")) {
            String[] bits = host.split("\\."); account = bits[0]; service = bits[1];
            serviceUnwrappedPath = unwrapped;
        } else {
            if (!(host.equals("127.0.0.1") || host.equals("localhost"))) return null;
            String[] parts = path.split("/", 3);
            String[] unwrappedParts = unwrapped.split("/", 3);
            if (parts.length < 2 || unwrappedParts.length != parts.length || !parts[1].equals(unwrappedParts[1])) return null;
            String firstSegment = parts[1];
            String resourcePath = parts.length == 3 ? parts[2] : "";
            String unwrappedResourcePath = unwrappedParts.length == 3 ? unwrappedParts[2] : "";
            if (isInterceptedBeforeStorageTerminal(path.substring(1), firstSegment, headers, q)
                    || isInterceptedBeforeStorageTerminal(unwrapped.substring(1), firstSegment, headers, q)) {
                return null;
            }
            if (firstSegment.endsWith("-queue")) {
                service = "queue";
                account = firstSegment.substring(0, firstSegment.length() - 6);
            } else {
                account = firstSegment;
                service = resolvePathStyleStorageService(headers, q, resourcePath);
                String unwrappedService = resolvePathStyleStorageService(headers, q, unwrappedResourcePath);
                if (!service.equals(unwrappedService)) return null;
            }
            path = parts.length == 3 ? "/" + resourcePath : "/";
            serviceUnwrappedPath = unwrappedParts.length == 3 ? "/" + unwrappedResourcePath : "/";
        }
        if (!account.matches("[a-z0-9]{3,24}")) return null;
        String comp = q.getOrDefault("comp", List.of("")).getFirst();
        String method = r.getMethod();
        String action = null;
        int segments = (int) Arrays.stream(path.split("/")).filter(v -> !v.isEmpty()).count();
        if (service.equals("blob")) {
            if (headers.containsKey("x-ms-copy-source") || headers.containsKey("x-ms-rename-source")) return null;
            List<String> restype = q.getOrDefault("restype", List.of(""));
            boolean container = restype.equals(List.of("container"));
            if (!restype.equals(List.of("")) && !container) return null;
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
                    case "POST" -> segments == 2 ? "/add/action" : null;
                    case "GET" -> segments == 2 ? (q.getOrDefault("peekonly", List.of("false")).equals(List.of("true")) ? "/read" : "/process/action") : null;
                    case "DELETE" -> "/delete";
                    case "PUT" -> segments == 3 ? "/write" : null;
                    default -> null;
                };
                if (operation != null) action = prefix + "/messages" + operation;
            }
        }
        if (action != null && action.endsWith("null")) action = null;
        return new Target(account, service, path, serviceUnwrappedPath, action);
    }
    private static String suffix(String method) {
        return switch (method) { case "GET", "HEAD" -> "/read"; case "PUT" -> "/write"; case "DELETE" -> "/delete"; default -> null; };
    }
}
