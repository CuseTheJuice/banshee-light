package com.sparrowwallet.sparrow.io;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTOutput;
import com.sparrowwallet.drongo.psbt.PSBTParseException;
import com.sparrowwallet.drongo.wallet.WalletModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Banshee Desktop talks to Banshee Studio over HTTPS. USB signing stays on Desktop.
 * Studio signing, when enabled, is Bluetooth only.
 */
public final class StudioSignClient {
    private static final Logger log = LoggerFactory.getLogger(StudioSignClient.class);
    public static final String STUDIO_PATH = "studio";
    private static final Duration POLL = Duration.ofMillis(750);
    private static final Duration SIGN_TIMEOUT = Duration.ofSeconds(180);
    private static final Duration XPUB_TIMEOUT = Duration.ofSeconds(30);
    private static final ExecutorService ACTIVITY = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "banshee-studio-activity");
        thread.setDaemon(true);
        return thread;
    });

    private StudioSignClient() {
    }

    /** True only when Studio signing is switched on and a link code is set. Otherwise Light signs over USB or Bluetooth. */
    public static boolean isStudioPreferred() {
        Config config = Config.get();
        return config.isBansheeStudioSigning() && config.hasBansheeStudioLink();
    }

    public static boolean usesStudio(Device device) {
        return device != null && STUDIO_PATH.equals(device.getPath());
    }

    public static LinkStatus probe() {
        if(!Config.get().hasBansheeStudioLink()) {
            return LinkStatus.fail("Paste a link code from Banshee Studio first.");
        }
        try {
            HttpResponse<String> res = request("GET", "/api/device", null, Duration.ofSeconds(5));
            JsonObject body = parseBody(res);
            if(res.statusCode() == 200) {
                boolean connected = !body.has("connected") || body.get("connected").getAsBoolean();
                String fp = body.has("fingerprint") && !body.get("fingerprint").isJsonNull()
                        ? body.get("fingerprint").getAsString().trim() : "";
                if(!fp.isEmpty()) {
                    Config.get().setBansheeStudioFingerprint(fp);
                }
                if(!connected) {
                    if(!isStudioPreferred()) {
                        return LinkStatus.ok("Banshee Studio is reachable. USB signing does not need a Studio Bluetooth session. Activity will log here.");
                    }
                    return LinkStatus.fail(fp.isEmpty()
                            ? "Banshee Studio is reachable. Connect Banshee Wallet over Bluetooth in Studio to sign."
                            : "Banshee Studio is reachable, but Banshee Wallet " + fp + " is not on Bluetooth there.");
                }
                StringBuilder msg = new StringBuilder("Connected to Banshee Studio");
                if(!fp.isEmpty()) {
                    msg.append(" · ").append(fp);
                }
                if(body.has("locked") && body.get("locked").getAsBoolean()) {
                    msg.append(" · locked");
                }
                msg.append(isStudioPreferred() ? " · Bluetooth signing." : " · activity log.");
                return LinkStatus.ok(msg.toString());
            }
            String err = body.has("error") ? body.get("error").getAsString() : ("HTTP " + res.statusCode());
            if(res.statusCode() == 404) {
                return LinkStatus.fail("Banshee Studio is reachable, but no Banshee Wallet is connected there.");
            }
            if(res.statusCode() == 401) {
                return LinkStatus.fail("Generate a link code in Banshee Studio first.");
            }
            if(res.statusCode() == 403) {
                return LinkStatus.fail("Bad link code. Generate a new one in Banshee Studio and paste it here.");
            }
            return LinkStatus.fail(err);
        } catch(Exception e) {
            return LinkStatus.fail(friendly(e));
        }
    }

    /** Presence of the Banshee Wallet held by Studio, or null when Studio has none connected. */
    public static DeviceState deviceState() throws ImportException {
        try {
            HttpResponse<String> res = request("GET", "/api/device", null, Duration.ofSeconds(5));
            if(res.statusCode() == 404) {
                return null;
            }
            JsonObject body = parse(res, "Banshee Studio is not connected to a Banshee Wallet");
            boolean connected = !body.has("connected") || body.get("connected").getAsBoolean();
            String fingerprint = body.has("fingerprint") && !body.get("fingerprint").isJsonNull()
                    ? body.get("fingerprint").getAsString().trim() : null;
            if(fingerprint != null && !fingerprint.isEmpty()) {
                Config.get().setBansheeStudioFingerprint(fingerprint);
            }
            if(!connected) {
                return null;
            }
            boolean ready = body.has("ready") && body.get("ready").getAsBoolean();
            boolean locked = body.has("locked") && body.get("locked").getAsBoolean();
            return new DeviceState(fingerprint == null || fingerprint.isEmpty() ? null : fingerprint, ready, locked);
        } catch(ImportException e) {
            throw e;
        } catch(Exception e) {
            log.debug("Studio device poll failed: {}", e.getMessage());
            throw new ImportException(friendly(e), e);
        }
    }

    /**
     * Always returns the Studio device when a link is configured. A missed presence poll must not
     * hide the Sign button — the job is posted first and Studio shows it.
     */
    public static Device enumerate() {
        Device device = studioDevice();
        String fingerprint = null;
        try {
            DeviceState state = deviceState();
            if(state != null) {
                fingerprint = state.fingerprint();
            }
        } catch(ImportException e) {
            log.debug("Studio presence: {}", e.getMessage());
        }
        if(fingerprint == null) {
            String remembered = Config.get().getBansheeStudioFingerprint();
            fingerprint = remembered.isEmpty() ? null : remembered;
        }
        if(fingerprint != null) {
            device.setFingerprint(fingerprint);
        }
        return device;
    }

    /**
     * Stand-in shown when a link code is set but Studio is not holding the wallet. Signing over USB
     * would fight Studio for the serial port, so the device is listed with the reason instead of
     * quietly falling back to it.
     */
    public static Device unavailableDevice(String reason) {
        Device device = studioDevice();
        String lastFingerprint = Config.get().getBansheeStudioFingerprint();
        if(!lastFingerprint.isEmpty()) {
            device.setFingerprint(lastFingerprint);
        }
        device.setError(reason == null || reason.isBlank()
                ? "Banshee Studio is not connected to a Banshee Wallet. Open Banshee Studio and click Connect."
                : reason);
        return device;
    }

    private static Device studioDevice() {
        Device device = new Device();
        device.setType("banshee");
        device.setPath(STUDIO_PATH);
        device.setModel(WalletModel.BANSHEE);
        device.setNeedsPinSent(false);
        device.setNeedsPassphraseSent(false);
        device.setCard(false);
        return device;
    }

    public static ExtendedKey getXpub(String derivationPath) throws ImportException {
        try {
            JsonObject req = new JsonObject();
            req.addProperty("network", networkName());
            req.addProperty("path", derivationPath);
            HttpResponse<String> created = request("POST", "/api/xpub", req.toString(), Duration.ofSeconds(10));
            JsonObject job = parse(created, "Banshee Studio xpub request failed");
            JsonObject done = waitForJob(job.get("id").getAsString(), XPUB_TIMEOUT);
            if(!done.has("xpub") || done.get("xpub").isJsonNull()) {
                throw new ImportException("Banshee Studio returned no xpub");
            }
            return ExtendedKey.fromDescriptor(done.get("xpub").getAsString().trim());
        } catch(ImportException e) {
            throw e;
        } catch(Exception e) {
            throw new ImportException(friendly(e), e);
        }
    }

    public static PSBT sign(PSBT psbt, Consumer<String> status) throws SignTransactionException {
        SignTransactionException last = null;
        for(int attempt = 1; attempt <= 4; attempt++) {
            try {
                return signOnce(psbt, status);
            } catch(SignTransactionException e) {
                last = e;
                if(!isStudioDisconnected(e) || attempt == 4) {
                    throw e;
                }
                status.accept("Studio is opening Banshee Wallet…");
                try {
                    Thread.sleep(2000);
                } catch(InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
        throw last != null ? last : new SignTransactionException("Banshee Studio sign failed");
    }

    private static PSBT signOnce(PSBT psbt, Consumer<String> status) throws SignTransactionException {
        try {
            byte[] psbtBytes = psbt.getForExport().serialize();
            String b64 = Base64.getEncoder().encodeToString(psbtBytes);
            PaymentSummary payment = summarize(psbt);
            JsonObject req = new JsonObject();
            req.addProperty("network", networkName());
            req.addProperty("psbt", b64);
            req.addProperty("paymentSats", payment.sats);
            req.addProperty("address", payment.address);
            req.addProperty("feeSats", payment.feeSats);
            status.accept("Sending to Banshee Studio…");
            HttpResponse<String> created = request("POST", "/api/sign", req.toString(), Duration.ofSeconds(10));
            JsonObject job = parse(created, "Banshee Studio sign request failed");
            status.accept("Open the Sign tab in Banshee Studio. Unlock if locked, then confirm on Banshee Wallet.");
            JsonObject done = waitForJob(job.get("id").getAsString(), SIGN_TIMEOUT);
            if(!done.has("signedPsbt") || done.get("signedPsbt").isJsonNull()) {
                throw new SignTransactionException("Banshee Studio returned no signed PSBT");
            }
            return combineSigned(psbt, done.get("signedPsbt").getAsString());
        } catch(SignTransactionException e) {
            throw e;
        } catch(Exception e) {
            throw new SignTransactionException(friendly(e), e);
        }
    }

    private static boolean isStudioDisconnected(Exception e) {
        String msg = e.getMessage() == null ? "" : e.getMessage().toLowerCase();
        return msg.contains("not connected");
    }

    /**
     * Report what Desktop did with the wallet so the Studio Sign tab can show it. Studio cannot watch
     * the serial port while Desktop owns it, so this push is the only source of activity there. Sent on
     * a daemon thread and never allowed to fail into the caller: a log post must not break signing.
     */
    public static void logActivity(String event, String status, String detail) {
        JsonObject body = activityBody(event, status);
        if(body == null) {
            return;
        }
        if(detail != null && !detail.isBlank()) {
            body.addProperty("detail", detail);
        }
        postActivity(body);
    }

    public static void logSignActivity(String status, PSBT psbt, String walletName, String error) {
        JsonObject body = activityBody("sign", status);
        if(body == null) {
            return;
        }
        if(walletName != null && !walletName.isBlank()) {
            body.addProperty("wallet", walletName);
        }
        if(error != null && !error.isBlank()) {
            body.addProperty("error", error);
        }
        try {
            PaymentSummary payment = summarize(psbt);
            body.addProperty("paymentSats", payment.sats());
            body.addProperty("address", payment.address());
            body.addProperty("feeSats", payment.feeSats());
        } catch(Exception e) {
            log.debug("Could not summarize PSBT for the Studio activity log", e);
        }
        postActivity(body);
    }

    private static JsonObject activityBody(String event, String status) {
        if(!Config.get().hasBansheeStudioLink()) {
            return null;
        }
        JsonObject body = new JsonObject();
        body.addProperty("event", event);
        body.addProperty("status", status);
        body.addProperty("transport", isStudioPreferred() ? "studio" : "usb");
        body.addProperty("network", networkName());
        return body;
    }

    private static void postActivity(JsonObject body) {
        ACTIVITY.submit(() -> {
            try {
                request("POST", "/api/activity", body.toString(), Duration.ofSeconds(5));
            } catch(Exception e) {
                log.debug("Could not post to the Studio activity log: {}", e.getMessage());
            }
        });
    }

    private static PaymentSummary summarize(PSBT psbt) {
        long sats = 0;
        String address = "";
        for(PSBTOutput out : psbt.getPsbtOutputs()) {
            Map<ECKey, ?> derived = out.getDerivedPublicKeys();
            if(derived != null && !derived.isEmpty()) {
                continue;
            }
            Address addr = out.getScript() != null ? out.getScript().getToAddress() : null;
            if(addr == null) {
                continue;
            }
            Long amount = out.getAmount();
            sats = amount == null ? 0L : amount;
            address = addr.toString();
            break;
        }
        Long fee = psbt.getFee();
        return new PaymentSummary(sats, address, fee == null ? 0L : fee);
    }

    private static PSBT combineSigned(PSBT original, String signedB64) throws SignTransactionException {
        try {
            PSBT devicePsbt = parseDeviceSignedPsbt(signedB64);
            if(devicePsbt.getPsbtInputs().size() != original.getPsbtInputs().size()) {
                throw new SignTransactionException("Banshee Wallet signed PSBT is incomplete (got "
                        + devicePsbt.getPsbtInputs().size() + " inputs, expected "
                        + original.getPsbtInputs().size() + ")");
            }
            boolean anySig = devicePsbt.getPsbtInputs().stream()
                    .anyMatch(input -> !input.getPartialSignatures().isEmpty());
            if(!anySig) {
                throw new SignTransactionException("Banshee Wallet returned a PSBT with no signatures");
            }
            PSBT combined = original.copy();
            try {
                combined.combine(devicePsbt);
            } catch(IllegalArgumentException e) {
                for(int i = 0; i < combined.getPsbtInputs().size(); i++) {
                    combined.getPsbtInputs().get(i).getPartialSignatures()
                            .putAll(devicePsbt.getPsbtInputs().get(i).getPartialSignatures());
                }
            }
            return combined;
        } catch(PSBTParseException e) {
            throw new SignTransactionException("Invalid signed PSBT from Banshee Wallet: " + e.getMessage(), e);
        }
    }

    private static PSBT parseDeviceSignedPsbt(String signedB64) throws PSBTParseException, SignTransactionException {
        String cleaned = signedB64 == null ? "" : signedB64.replaceAll("\\s+", "");
        if(cleaned.isEmpty()) {
            throw new SignTransactionException("Banshee Wallet returned an empty signed PSBT");
        }
        byte[] signedBytes;
        try {
            signedBytes = Base64.getDecoder().decode(cleaned);
        } catch(IllegalArgumentException e) {
            try {
                signedBytes = Base64.getMimeDecoder().decode(signedB64);
            } catch(IllegalArgumentException e2) {
                throw new SignTransactionException("Banshee Wallet returned invalid Base64", e);
            }
        }
        return new PSBT(signedBytes, false);
    }

    private static JsonObject waitForJob(String id, Duration timeout) throws Exception {
        long deadline = System.currentTimeMillis() + timeout.toMillis();
        while(System.currentTimeMillis() < deadline) {
            HttpResponse<String> res = request("GET", "/api/job/" + id, null, Duration.ofSeconds(5));
            JsonObject job = parse(res, "Banshee Studio job missing");
            String status = job.has("status") ? job.get("status").getAsString() : "";
            if("done".equals(status)) {
                return job;
            }
            if("error".equals(status)) {
                String err = job.has("error") && !job.get("error").isJsonNull()
                        ? job.get("error").getAsString() : "Banshee Studio job failed";
                throw new ImportException(friendlyDeviceError(err));
            }
            Thread.sleep(POLL.toMillis());
        }
        throw new ImportException("Timed out waiting for Banshee Studio / Banshee Wallet. Unlock if locked, then approve on the device.");
    }

    private static String friendlyDeviceError(String err) {
        String lower = err == null ? "" : err.toLowerCase();
        if(lower.contains("locked")) {
            return "Banshee Wallet is locked. Enter the side-button sequence, then try again.";
        }
        if(lower.contains("rejected") || lower.contains("cancel")) {
            return "Rejected on Banshee Wallet (left button).";
        }
        return err;
    }

    private static HttpResponse<String> request(String method, String path, String json, Duration timeout) throws Exception {
        Config config = Config.get();
        String base = config.getBansheeStudioUrl().replaceAll("/+$", "");
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(base + path))
                .timeout(timeout)
                .header("Authorization", "Bearer " + config.getBansheeStudioToken());
        if(json != null) {
            builder.header("Content-Type", "application/json");
            builder.method(method, HttpRequest.BodyPublishers.ofString(json));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        return client().send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static JsonObject parseBody(HttpResponse<String> res) {
        String raw = res.body() == null ? "" : res.body();
        try {
            return JsonParser.parseString(raw.isEmpty() ? "{}" : raw).getAsJsonObject();
        } catch(Exception e) {
            return new JsonObject();
        }
    }

    private static JsonObject parse(HttpResponse<String> res, String fallback) throws ImportException {
        JsonObject obj = parseBody(res);
        if(res.statusCode() >= 400) {
            String err = obj.has("error") ? obj.get("error").getAsString() : fallback + " (HTTP " + res.statusCode() + ")";
            throw new ImportException(err);
        }
        return obj;
    }

    private static HttpClient client() throws Exception {
        TrustManager[] trustAll = new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };
        SSLContext ssl = SSLContext.getInstance("TLS");
        ssl.init(null, trustAll, new SecureRandom());
        SSLParameters params = ssl.getDefaultSSLParameters();
        params.setEndpointIdentificationAlgorithm("");
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .sslContext(ssl)
                .sslParameters(params)
                .build();
    }

    private static String networkName() {
        return Network.getCanonical().getName();
    }

    private static String friendly(Exception e) {
        String msg = e.getMessage();
        if(msg == null || msg.isBlank()) {
            return "Could not reach Banshee Studio at " + Config.get().getBansheeStudioUrl();
        }
        if(msg.contains("SSL") || msg.contains("PKIX") || msg.contains("certificate")) {
            return "Could not trust Banshee Studio TLS. Check the URL and that Banshee Studio is running.";
        }
        return msg;
    }

    private record PaymentSummary(long sats, String address, long feeSats) {
    }

    public record DeviceState(String fingerprint, boolean ready, boolean locked) {
    }

    public record LinkStatus(boolean ok, String message) {
        static LinkStatus ok(String message) {
            return new LinkStatus(true, message);
        }

        static LinkStatus fail(String message) {
            return new LinkStatus(false, message);
        }
    }
}
