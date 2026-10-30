package ai.lmctl.azuresim;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Escape values at insertion boundaries, never the completed response template. */
final class ResponseTemplates {
    private static final ObjectMapper JSON = new ObjectMapper();

    static String json(String value) {
        try { return JSON.writeValueAsString(value); }
        catch (JsonProcessingException e) { throw new IllegalStateException("Cannot encode response", e); }
    }

    static String xml(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("\"", "&quot;").replace("'", "&apos;");
    }
}
