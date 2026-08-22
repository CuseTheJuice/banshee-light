package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.ExtendedKey;
import com.sparrowwallet.drongo.IOUtils;
import com.sparrowwallet.drongo.OsType;
import com.sparrowwallet.drongo.OutputDescriptor;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.silentpayments.SilentPaymentScanAddress;
import com.sparrowwallet.drongo.wallet.StandardAccount;
import com.sparrowwallet.drongo.wallet.WalletModel;
import com.sparrowwallet.lark.BansheeBle;
import com.sparrowwallet.lark.BansheeSerialProbe;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.HardwareType;
import com.sparrowwallet.lark.Lark;
import com.sparrowwallet.lark.bitbox02.BitBoxFileNoiseConfig;
import com.sparrowwallet.lark.trezor.TrezorFileNoiseConfig;
import com.sparrowwallet.sparrow.AppServices;
import com.sparrowwallet.sparrow.SparrowWallet;
import com.sparrowwallet.sparrow.control.BitBoxPairingDialog;
import com.sparrowwallet.sparrow.control.TextfieldDialog;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.MapChangeListener;
import javafx.collections.ObservableMap;
import javafx.concurrent.ScheduledService;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.TextFormatter;
import javafx.scene.layout.HBox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardException;
import javax.smartcardio.CardNotPresentException;
import java.io.File;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

public class Hwi {
    private static final Logger log = LoggerFactory.getLogger(Hwi.class);
    private static final String HWI_HOME_DIR = "hwi";
    private static final String LARK_HOME_DIR = "lark";
    private static final String BITBOX_FILENAME = "bitbox02.json";
    private static final String TREZOR_FILENAME = "trezor.json";

    private static volatile boolean isPromptActive = false;

    private static final AtomicBoolean bansheeSeen = new AtomicBoolean(false);

    private final Set<byte[]> newDeviceRegistrations = new HashSet<>();

    static {
        deleteHwiDir();
    }

    public List<Device> enumerate(String passphrase) throws ImportException {
        List<Device> devices = new ArrayList<>();
        devices.addAll(enumerateUsb(passphrase, true));
        devices.addAll(enumerateCard());
        return devices;
    }

    public List<Device> enumeratePresence(String passphrase) throws ImportException {
        return enumerateUsb(passphrase, false);
    }

    private List<Device> enumerateUsb(String passphrase, boolean initializeFingerprint) throws ImportException {
        try {
            if(StudioSignClient.isStudioPreferred()) {
                BansheeSerialProbe.setSkip(true);
                Device studio = StudioSignClient.enumerate();
                reportBansheePresence(true, "Banshee Wallet via Banshee Studio");
                return List.of(studio);
            }
            List<Device> devices = new ArrayList<>();
            BansheeSerialProbe.setSkip(false);
            Lark lark = getLark(passphrase);
            isPromptActive = initializeFingerprint;
            List<com.sparrowwallet.lark.HardwareClient> clients = initializeFingerprint ? lark.enumerate() : lark.enumerateWithoutFingerprint();
            devices.addAll(clients.stream()
                    .filter(client -> client.getHardwareType() == HardwareType.LEDGER
                            || client.getHardwareType() == HardwareType.BANSHEE)
                    .map(Device::fromHardwareClient).toList());
            boolean banshee = clients.stream().anyMatch(client -> client.getHardwareType() == HardwareType.BANSHEE);
            boolean ble = clients.stream().anyMatch(client -> client.getHardwareType() == HardwareType.BANSHEE
                    && BansheeBle.isBlePath(client.getPath()));
            reportBansheePresence(banshee, ble ? "Banshee Wallet over Bluetooth" : "Banshee Wallet over USB");
            return devices;
        } catch(Throwable e) {
            log.error("Error enumerating USB devices", e);
            throw new ImportException(e.getMessage() == null || e.getMessage().isEmpty() ? "Error scanning, check devices are ready" : e.getMessage(), e);
        } finally {
            isPromptActive = false;
        }
    }

    private List<Device> enumerateCard() {
        return List.of();
    }

    /** Only log the transition, so a scan every few seconds does not fill the Studio activity log. */
    private static void reportBansheePresence(boolean present, String how) {
        if(bansheeSeen.getAndSet(present) == present) {
            return;
        }
        StudioSignClient.logActivity(present ? "connected" : "disconnected", "info", how);
    }

    public boolean promptPin(Device device) throws ImportException {
        try {
            Lark lark = getLark();
            boolean result = lark.promptPin(device.getType(), device.getPath());
            isPromptActive = true;
            return result;
        } catch(DeviceException e) {
            throw new ImportException(e.getMessage(), e);
        } catch(RuntimeException e) {
            log.error("Error prompting pin", e);
            throw e;
        }
    }

    public boolean sendPin(Device device, String pin) throws ImportException {
        try {
            Lark lark = getLark();
            boolean result = lark.sendPin(device.getType(), device.getPath(), pin);
            isPromptActive = false;
            return result;
        } catch(DeviceException e) {
            throw new ImportException(e.getMessage(), e);
        } catch(RuntimeException e) {
            log.error("Error sending pin", e);
            throw e;
        }
    }

    public boolean togglePassphrase(Device device) throws ImportException {
        try {
            Lark lark = getLark();
            boolean result = lark.togglePassphrase(device.getType(), device.getPath());
            isPromptActive = false;
            return result;
        } catch(DeviceException e) {
            throw new ImportException(e.getMessage(), e);
        } catch(RuntimeException e) {
            log.error("Error toggling passphrase", e);
            throw e;
        }
    }

    public Map<WalletType, ExtendedKey> getXpubs(Device device, String passphrase, Map<WalletType, String> accountDerivationPaths, Map<WalletType, ExtendedKey> accountXpubs) throws ImportException {
        for(Map.Entry<WalletType, String> entry : accountDerivationPaths.entrySet()) {
            accountXpubs.put(entry.getKey(), getXpub(device, passphrase, entry.getValue()));
        }

        return accountXpubs;
    }

    public ExtendedKey getXpub(Device device, String passphrase, String derivationPath) throws ImportException {
        try {
            if(StudioSignClient.usesStudio(device)) {
                ExtendedKey xpub = StudioSignClient.getXpub(derivationPath);
                isPromptActive = false;
                StudioSignClient.logActivity("xpub", "ok", derivationPath);
                return xpub;
            }
            BansheeSerialProbe.setSkip(false);
            Lark lark = getLark(passphrase);
            ExtendedKey xpub = device.getModel() == WalletModel.BANSHEE
                    ? lark.getPubKeyAtPath(device.getType(), derivationPath)
                    : lark.getPubKeyAtPath(device.getType(), device.getPath(), derivationPath);
            isPromptActive = false;
            StudioSignClient.logActivity("xpub", "ok", derivationPath);
            return xpub;
        } catch(DeviceException e) {
            StudioSignClient.logActivity("xpub", "error", e.getMessage());
            throw new ImportException(e.getMessage(), e);
        } catch(RuntimeException e) {
            StudioSignClient.logActivity("xpub", "error", e.getMessage());
            log.error("Error retrieving xpub", e);
            throw e;
        }
    }

    public SilentPaymentScanAddress getSpscan(Device device, String passphrase, String derivationPath) throws ImportException {
        try {
            Lark lark = getLark(passphrase);
            SilentPaymentScanAddress spscan = lark.getSpscanAtPath(device.getType(), device.getPath(), derivationPath);
            isPromptActive = false;
            return spscan;
        } catch(DeviceException e) {
            throw new ImportException(e.getMessage(), e);
        } catch(RuntimeException e) {
            log.error("Error retrieving spscan", e);
            throw e;
        }
    }

    public String displayAddress(Device device, String passphrase, ScriptType scriptType, OutputDescriptor addressDescriptor,
                                 OutputDescriptor walletDescriptor, String walletName, byte[] walletRegistration) throws DisplayAddressException {
        try {
            if(!Arrays.asList(ScriptType.ADDRESSABLE_TYPES).contains(scriptType)) {
                throw new IllegalArgumentException("Cannot display address for script type " + scriptType + ": Only addressable types supported");
            }

            isPromptActive = true;
            Lark lark = getLark(passphrase, walletDescriptor, walletName, walletRegistration);
            String address = lark.displayAddress(device.getType(), device.getPath(), addressDescriptor);
            newDeviceRegistrations.addAll(lark.getWalletRegistrations().values());
            newDeviceRegistrations.remove(walletRegistration);
            StudioSignClient.logActivity("address", "ok", address);
            return address;
        } catch(DeviceException e) {
            StudioSignClient.logActivity("address", "error", e.getMessage());
            throw new DisplayAddressException(e.getMessage(), e);
        } catch(RuntimeException e) {
            StudioSignClient.logActivity("address", "error", e.getMessage());
            log.error("Error displaying address", e);
            throw e;
        } finally {
            isPromptActive = false;
        }
    }

    public String signMessage(Device device, String passphrase, String message, String derivationPath) throws SignMessageException {
        try {
            isPromptActive = true;
            Lark lark = getLark(passphrase);
            String signature = lark.signMessage(device.getType(), device.getPath(), message, derivationPath);
            StudioSignClient.logActivity("message", "ok", derivationPath);
            return signature;
        } catch(DeviceException e) {
            StudioSignClient.logActivity("message", "error", e.getMessage());
            throw new SignMessageException(e.getMessage(), e);
        } catch(RuntimeException e) {
            StudioSignClient.logActivity("message", "error", e.getMessage());
            log.error("Error signing message", e);
            throw e;
        } finally {
            isPromptActive = false;
        }
    }

    public PSBT signPSBT(Device device, String passphrase, PSBT psbt,
                         OutputDescriptor walletDescriptor, String walletName, byte[] walletRegistration,
                         Consumer<String> status) throws SignTransactionException {
        try {
            isPromptActive = true;
            StudioSignClient.logSignActivity("started", psbt, walletName, null);
            PSBT signed;
            if(StudioSignClient.usesStudio(device)) {
                signed = StudioSignClient.sign(psbt, status);
            } else {
                Lark lark = getLark(passphrase, walletDescriptor, walletName, walletRegistration);
                signed = lark.signTransaction(device.getType(), device.getPath(), psbt);
                newDeviceRegistrations.addAll(lark.getWalletRegistrations().values());
                newDeviceRegistrations.remove(walletRegistration);
            }
            StudioSignClient.logSignActivity("ok", psbt, walletName, null);
            return signed;
        } catch(DeviceException e) {
            StudioSignClient.logSignActivity("error", psbt, walletName, e.getMessage());
            throw new SignTransactionException(e.getMessage(), e);
        } catch(SignTransactionException e) {
            StudioSignClient.logSignActivity("error", psbt, walletName, e.getMessage());
            throw e;
        } catch(RuntimeException e) {
            StudioSignClient.logSignActivity("error", psbt, walletName, e.getMessage());
            log.error("Error signing PSBT", e);
            throw e;
        } finally {
            isPromptActive = false;
        }
    }

    public BansheeEntropyReport getBansheeEntropyProof(Device device) throws ImportException {
        try {
            com.sparrowwallet.lark.BansheeEntropyReport report = getLark().getBansheeEntropyProof(device.getPath());
            return new BansheeEntropyReport(report.proof, report.rng);
        } catch(DeviceException e) {
            throw new ImportException(e.getMessage(), e);
        }
    }

    public static final class BansheeEntropyReport {
        public final String proof;
        public final String rng;

        public BansheeEntropyReport(String proof, String rng) {
            this.proof = proof == null ? "" : proof.trim();
            this.rng = rng == null ? "" : rng.trim();
        }
    }

    private Lark getLark() {
        return getLark(null);
    }

    private Lark getLark(String passphrase) {
        return getLark(passphrase, null, null, null);
    }

    private Lark getLark(String passphrase, OutputDescriptor walletDescriptor, String walletName, byte[] walletRegistration) {
        Lark lark = new Lark(AppServices.getHttpClientService());
        lark.setBitBoxNoiseConfig(new BitBoxFxNoiseConfig());
        lark.setTrezorNoiseConfig(new TrezorFxNoiseConfig());
        if(passphrase != null) {
            lark.setPassphrase(passphrase);
        }

        if(walletDescriptor != null && walletName != null) {
            if(walletRegistration != null) {
                lark.addWalletRegistration(walletDescriptor, walletName, walletRegistration);
            } else {
                lark.addWalletName(walletDescriptor, walletName);
            }
        }

        return lark;
    }

    private static void deleteHwiDir() {
        try {
            if(OsType.getCurrent() == OsType.MACOS || OsType.getCurrent() == OsType.WINDOWS) {
                File hwiHomeDir = new File(Storage.getCacheDir(), HWI_HOME_DIR);
                if(hwiHomeDir.exists()) {
                    IOUtils.deleteDirectory(hwiHomeDir);
                }
            }
        } catch(Exception e) {
            log.error("Error deleting hwi directory", e);
        }
    }

    public static class EnumerateService extends Service<List<Device>> {
        private final String passphrase;

        public EnumerateService(String passphrase) {
            this.passphrase = passphrase;
        }

        @Override
        protected Task<List<Device>> createTask() {
            return new Task<>() {
                protected List<Device> call() throws ImportException {
                    Hwi hwi = new Hwi();
                    return hwi.enumerate(passphrase);
                }
            };
        }
    }

    public static class ScheduledEnumerateService extends ScheduledService<List<Device>> {
        private final String passphrase;

        public ScheduledEnumerateService(String passphrase) {
            this.passphrase = passphrase;
        }

        @Override
        protected Task<List<Device>> createTask() {
            return new Task<>() {
                protected List<Device> call() throws ImportException {
                    if(!isPromptActive) {
                        Hwi hwi = new Hwi();
                        return hwi.enumeratePresence(passphrase);
                    }

                    return null;
                }
            };
        }
    }

    public static class PromptPinService extends Service<Boolean> {
        private final Device device;

        public PromptPinService(Device device) {
            this.device = device;
        }

        @Override
        protected Task<Boolean> createTask() {
            return new Task<>() {
                protected Boolean call() throws ImportException {
                    Hwi hwi = new Hwi();
                    return hwi.promptPin(device);
                }
            };
        }
    }

    public static class SendPinService extends Service<Boolean> {
        private final Device device;
        private final String pin;

        public SendPinService(Device device, String pin) {
            this.device = device;
            this.pin = pin;
        }

        @Override
        protected Task<Boolean> createTask() {
            return new Task<>() {
                protected Boolean call() throws ImportException {
                    Hwi hwi = new Hwi();
                    return hwi.sendPin(device, pin);
                }
            };
        }
    }

    public static class TogglePassphraseService extends Service<Boolean> {
        private final Device device;

        public TogglePassphraseService(Device device) {
            this.device = device;
        }

        @Override
        protected Task<Boolean> createTask() {
            return new Task<>() {
                protected Boolean call() throws ImportException {
                    Hwi hwi = new Hwi();
                    return hwi.togglePassphrase(device);
                }
            };
        }
    }

    public static class DisplayAddressService extends Service<String> {
        private final Device device;
        private final String passphrase;
        private final ScriptType scriptType;
        private final OutputDescriptor addressDescriptor;
        private final OutputDescriptor walletDescriptor;
        private final String walletName;
        private final byte[] walletRegistration;
        private final Set<byte[]> newDeviceRegistrations = new HashSet<>();

        public DisplayAddressService(Device device, String passphrase, ScriptType scriptType, OutputDescriptor addressDescriptor, OutputDescriptor walletDescriptor, String walletName, byte[] walletRegistration) {
            this.device = device;
            this.passphrase = passphrase;
            this.scriptType = scriptType;
            this.addressDescriptor = addressDescriptor;
            this.walletDescriptor = walletDescriptor;
            this.walletName = walletName;
            this.walletRegistration = walletRegistration;
        }

        public Set<byte[]> getNewDeviceRegistrations() {
            return newDeviceRegistrations;
        }

        @Override
        protected Task<String> createTask() {
            return new Task<>() {
                protected String call() throws DisplayAddressException {
                    Hwi hwi = new Hwi();
                    String address = hwi.displayAddress(device, passphrase, scriptType, addressDescriptor, walletDescriptor, walletName, walletRegistration);
                    newDeviceRegistrations.addAll(hwi.newDeviceRegistrations);
                    return address;
                }
            };
        }
    }

    public static class SignMessageService extends Service<String> {
        private final Device device;
        private final String passphrase;
        private final String message;
        private final String derivationPath;

        public SignMessageService(Device device, String passphrase, String message, String derivationPath) {
            this.device = device;
            this.passphrase = passphrase;
            this.message = message;
            this.derivationPath = derivationPath;
        }

        @Override
        protected Task<String> createTask() {
            return new Task<>() {
                protected String call() throws SignMessageException {
                    Hwi hwi = new Hwi();
                    return hwi.signMessage(device, passphrase, message, derivationPath);
                }
            };
        }
    }

    public static class GetXpubService extends Service<ExtendedKey> {
        private final Device device;
        private final String passphrase;
        private final String derivationPath;

        public GetXpubService(Device device, String passphrase, String derivationPath) {
            this.device = device;
            this.passphrase = passphrase;
            this.derivationPath = derivationPath;
        }

        @Override
        protected Task<ExtendedKey> createTask() {
            return new Task<>() {
                protected ExtendedKey call() throws ImportException {
                    Hwi hwi = new Hwi();
                    return hwi.getXpub(device, passphrase, derivationPath);
                }
            };
        }
    }

    public static class GetSpscanService extends Service<SilentPaymentScanAddress> {
        private final Device device;
        private final String passphrase;
        private final String derivationPath;

        public GetSpscanService(Device device, String passphrase, String derivationPath) {
            this.device = device;
            this.passphrase = passphrase;
            this.derivationPath = derivationPath;
        }

        @Override
        protected Task<SilentPaymentScanAddress> createTask() {
            return new Task<>() {
                protected SilentPaymentScanAddress call() throws ImportException {
                    Hwi hwi = new Hwi();
                    return hwi.getSpscan(device, passphrase, derivationPath);
                }
            };
        }
    }

    public static class GetXpubsService extends Service<Map<WalletType, ExtendedKey>> {
        private final Device device;
        private final String passphrase;
        private final Map<WalletType, String> accountDerivationPaths;

        public GetXpubsService(Device device, String passphrase, Map<WalletType, String> accountDerivationPaths) {
            this.device = device;
            this.passphrase = passphrase;
            this.accountDerivationPaths = accountDerivationPaths;
        }

        @Override
        protected Task<Map<WalletType, ExtendedKey>> createTask() {
            return new Task<>() {
                protected Map<WalletType, ExtendedKey> call() throws ImportException {
                    Hwi hwi = new Hwi();
                    updateProgress(0, accountDerivationPaths.size());
                    ObservableMap<WalletType, ExtendedKey> accountXpubs = FXCollections.observableMap(new LinkedHashMap<>());
                    accountXpubs.addListener((MapChangeListener<? super WalletType, ? super ExtendedKey>) _ -> updateProgress(accountXpubs.size(), accountDerivationPaths.size()));
                    return hwi.getXpubs(device, passphrase, accountDerivationPaths, accountXpubs);
                }
            };
        }
    }

    public static class SignPSBTService extends Service<PSBT> {
        private final Device device;
        private final String passphrase;
        private final PSBT psbt;
        private final OutputDescriptor walletDescriptor;
        private final String walletName;
        private final byte[] walletRegistration;
        private final Set<byte[]> newDeviceRegistrations = new HashSet<>();

        public SignPSBTService(Device device, String passphrase, PSBT psbt, OutputDescriptor walletDescriptor, String walletName, byte[] walletRegistration) {
            this.device = device;
            this.passphrase = passphrase;
            this.psbt = psbt;
            this.walletDescriptor = walletDescriptor;
            this.walletName = walletName;
            this.walletRegistration = walletRegistration;
        }

        public Set<byte[]> getNewDeviceRegistrations() {
            return newDeviceRegistrations;
        }

        @Override
        protected Task<PSBT> createTask() {
            return new Task<>() {
                protected PSBT call() throws SignTransactionException {
                    Hwi hwi = new Hwi();
                    PSBT signed = hwi.signPSBT(device, passphrase, psbt, walletDescriptor, walletName, walletRegistration, this::updateMessage);
                    newDeviceRegistrations.addAll(hwi.newDeviceRegistrations);
                    return signed;
                }
            };
        }
    }

    public static class BansheeEntropyProofService extends Service<Hwi.BansheeEntropyReport> {
        private final Device device;

        public BansheeEntropyProofService(Device device) {
            this.device = device;
        }

        @Override
        protected Task<Hwi.BansheeEntropyReport> createTask() {
            return new Task<>() {
                protected Hwi.BansheeEntropyReport call() throws ImportException {
                    return new Hwi().getBansheeEntropyProof(device);
                }
            };
        }
    }

    private static final class BitBoxFxNoiseConfig extends BitBoxFileNoiseConfig {
        private static final AtomicBoolean attestationWarningShown = new AtomicBoolean(false);

        private BitBoxPairingDialog pairingDialog;

        public BitBoxFxNoiseConfig() {
            super(Path.of(Storage.getDataHome().getAbsolutePath(), LARK_HOME_DIR, BITBOX_FILENAME).toFile());
        }

        @Override
        public void attestationCheck(boolean result) {
            if(!result) {
                log.warn("BitBox02 attestation check failed, device may not be genuine");
                //Devices are opened repeatedly while enumerating, so warn only once per session
                if(attestationWarningShown.compareAndSet(false, true)) {
                    Platform.runLater(() -> AppServices.showWarningDialog("BitBox02 Attestation Failed",
                            "This BitBox02 did not pass the attestation check, which means it may not be a genuine device.\n\n" +
                                    "Do not use it to store funds until you have verified it externally."));
                }
            }
        }

        @Override
        public boolean showPairing(String code, DeviceResponse response) throws DeviceException {
            CountDownLatch latch = new CountDownLatch(1);
            AtomicBoolean confirmedDevice = new AtomicBoolean(false);

            Thread showPairingDeviceThread = new Thread(() -> {
                try {
                    isPromptActive = true;
                    confirmedDevice.set(response.call());
                    latch.countDown();
                } catch(DeviceException e) {
                    throw new RuntimeException(e);
                } finally {
                    isPromptActive = false;
                }
            });
            showPairingDeviceThread.start();

            Platform.runLater(() -> {
                pairingDialog = new BitBoxPairingDialog(code);
                pairingDialog.initOwner(AppServices.getActiveWindow());
                pairingDialog.show();
            });

            try {
                latch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            Platform.runLater(() -> {
                if(pairingDialog != null && pairingDialog.isShowing()) {
                    pairingDialog.setResult(ButtonType.APPLY);
                }
                if(!confirmedDevice.get()) {
                    AppServices.showWarningDialog("Pairing Refused", "Pairing was refused on the device.");
                }
            });

            return confirmedDevice.get();
        }
    }

    private static final class TrezorFxNoiseConfig extends TrezorFileNoiseConfig {
        private String deviceInfo;

        public TrezorFxNoiseConfig() {
            super(Path.of(Storage.getDataHome().getAbsolutePath(), LARK_HOME_DIR, TREZOR_FILENAME).toFile());
        }

        @Override
        public String promptForPairingCode() {
            CompletableFuture<String> future = new CompletableFuture<>();
            Platform.runLater(() -> {
                TextfieldDialog textfieldDialog = new TextfieldDialog();
                textfieldDialog.initOwner(AppServices.getActiveWindow());
                textfieldDialog.setTitle("Enter Pairing Code");
                textfieldDialog.setHeaderText("Enter the code shown on the " + deviceInfo + ":");
                textfieldDialog.getDialogPane().setPrefWidth(300);
                textfieldDialog.getEditor().setOnAction(_ -> textfieldDialog.setResult(textfieldDialog.getEditor().getText()));
                textfieldDialog.getEditor().setTextFormatter(new TextFormatter<>(change -> {
                    String newText = change.getControlNewText();
                    if(newText.matches("\\d*")) {
                        return change;
                    }
                    return null;
                }));
                textfieldDialog.getEditor().setStyle("-fx-font-size: 30px;");
                HBox.setMargin(textfieldDialog.getEditor(), new Insets(0, 65, 0, 65));
                textfieldDialog.getEditor().requestFocus();
                textfieldDialog.showAndWait().ifPresentOrElse(future::complete, () -> future.complete(null));
            });

            try {
                isPromptActive = true;
                return future.get(); // Block until dialog is closed
            } catch (InterruptedException | ExecutionException e) {
                Thread.currentThread().interrupt();
                return null;
            } finally {
                isPromptActive = false;
            }
        }

        @Override
        public boolean confirmPairing(String deviceInfo) {
            this.deviceInfo = deviceInfo;
            CompletableFuture<ButtonType> future = new CompletableFuture<>();
            Platform.runLater(() -> {
                AppServices.showAlertDialog("Pairing Required", "Pair the " + deviceInfo + " with " + SparrowWallet.APP_NAME + "?",
                        Alert.AlertType.CONFIRMATION, ButtonType.YES, ButtonType.NO).ifPresentOrElse(future::complete, () -> future.complete(null));
            });

            try {
                isPromptActive = true;
                return future.get() == ButtonType.YES; // Block until dialog is closed
            } catch (InterruptedException | ExecutionException e) {
                Thread.currentThread().interrupt();
                return false;
            } finally {
                isPromptActive = false;
            }
        }

        @Override
        public void displayPairingCode(String code) {
            super.displayPairingCode(code);
        }

        @Override
        public String getAppName() {
            return SparrowWallet.APP_NAME;
        }

        @Override
        public void pairingFailed(String reason) {
            Platform.runLater(() -> AppServices.showErrorDialog("Pairing Failed", "Pairing failed: " + reason));
        }

        @Override
        public void pairingSuccessful(String deviceInfo) {
            this.deviceInfo = deviceInfo;
            Platform.runLater(() -> AppServices.showSuccessDialog("Pairing Successful", "The " + deviceInfo + " has been successfully paired."));
        }
    }

    public record WalletType(ScriptType scriptType, StandardAccount standardAccount) {}
}
