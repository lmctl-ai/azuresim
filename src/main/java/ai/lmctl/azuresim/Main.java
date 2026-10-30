package ai.lmctl.azuresim;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.annotations.QuarkusMain;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

/** Distribution entrypoint; all Azure protocols remain upstream implementations. */
@QuarkusMain
public final class Main {
    private static final String VERSION = "@VERSION@";

    public static void main(String[] args) {
        if (args.length == 1 && args[0].equals("--version")) {
            System.out.println("azuresim " + VERSION);
            return;
        }
        if (args.length == 0 || (args.length == 1 && args[0].equals("--help"))) {
            System.out.println("azuresim " + VERSION + " (Floci-AZ 0.15.0)\n"
                + "Usage: azuresim serve|start [--port 4577] [--data-dir PATH] [--auth open|enforce] [--auth-config FILE]\n"
                + "       azuresim --version|--help\n"
                + "Serves HTTP on 127.0.0.1. Memory storage unless --data-dir is supplied.\n"
                + "Stop with Ctrl-C. Upstream logs go to stderr.");
            return;
        }
        if (!args[0].equals("serve") && !args[0].equals("start")) {
            fail("Expected serve or start");
        }
        int port = 4577;
        String data = null;
        String auth = System.getenv().getOrDefault("AZURESIM_AUTH", "open");
        String authFile = System.getenv("AZURESIM_AUTH_CONFIG");
        Set<String> seen = new HashSet<>();
        for (int i = 1; i < args.length; i++) {
            String option = args[i];
            if (!Set.of("--port", "--data-dir", "--auth", "--auth-config").contains(option) || !seen.add(option)) {
                fail("Unknown or duplicate option");
            }
            if (++i == args.length || args[i].isBlank()) fail("Missing option value");
            if (option.equals("--port")) {
                try { port = Integer.parseInt(args[i]); }
                catch (NumberFormatException e) { fail("Port must be an integer from 1 to 65535"); }
                if (port < 1 || port > 65535) fail("Port must be an integer from 1 to 65535");
            } else if (option.equals("--auth")) { auth = args[i];
            } else if (option.equals("--auth-config")) { authFile = args[i];
            } else {
                try { data = Path.of(args[i]).toAbsolutePath().toString(); }
                catch (RuntimeException e) { fail("Invalid data directory"); }
            }
        }
        try { StorageAuth.configure(auth, authFile); }
        catch (Exception ignored) { fail("Invalid auth configuration"); }
        // Distribution defaults take precedence over environment variables.
        System.setProperty("quarkus.http.host", "127.0.0.1");
        System.setProperty("quarkus.http.host-validation.require-localhost", "false");
        System.setProperty("quarkus.http.port", Integer.toString(port));
        System.setProperty("floci-az.port", Integer.toString(port));
        System.setProperty("floci-az.base-url", "http://127.0.0.1:" + port);
        System.setProperty("floci-az.tls.enabled", "false");
        System.setProperty("quarkus.log.console.stderr", "true");
        System.setProperty("floci-az.services.event-hub.enabled", "false");
        System.setProperty("floci-az.services.service-bus.start-on-boot", "false");
        System.setProperty("floci-az.storage.mode", data == null ? "memory" : "persistent");
        if (data != null) {
            System.setProperty("floci-az.storage.persistent-path", data);
            System.setProperty("floci-az.storage.host-persistent-path", data);
        }
        Quarkus.run(null, (code, error) -> {
            if (code != 0 || error != null) {
                if (error != null) error.printStackTrace(System.err);
                System.out.println("{\"ok\":false,\"error\":\"Emulator failed; see stderr\"}");
                System.exit(3);
            }
        });
    }

    private static void fail(String message) {
        System.out.print("""
            {"ok":false,"error":%s}
            """.formatted(ResponseTemplates.json(message)));
        System.exit(2);
    }
}
