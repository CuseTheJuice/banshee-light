// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.sparrow.control;

import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.lark.BansheeBle;
import com.sparrowwallet.lark.BansheeClient;
import com.sparrowwallet.lark.BansheeInfo;
import com.sparrowwallet.lark.BansheeOracle;
import com.sparrowwallet.lark.BansheeSerialProbe;
import com.sparrowwallet.lark.BansheeUnlockStatus;
import com.sparrowwallet.lark.BansheeWalletStatus;
import com.sparrowwallet.lark.DeviceException;
import com.sparrowwallet.lark.Lark;
import com.sparrowwallet.sparrow.AppServices;
import com.sparrowwallet.sparrow.io.BansheeBackupFile;
import com.sparrowwallet.sparrow.io.BansheeFlash;
import com.sparrowwallet.sparrow.io.EspSecureBootV2;
import javafx.application.Platform;
import javafx.concurrent.Service;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ChoiceDialog;
import javafx.scene.control.Dialog;
import javafx.scene.control.DialogPane;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextInputDialog;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class BansheeSetupDialog extends Dialog<Wallet> {
    private static final long DIALOG_TIMEOUT_MINUTES = 10;
    private static final long DETECT_TIMEOUT_SECONDS = 12;
    private static final String BOOTLOADER_ONLY =
            "Board is in download mode. Unplug without holding LEFT and plug in again, or use Flash.";

    private final TextArea log = new TextArea();
    private final Label status = new Label("Plug the board in over USB, or Scan Bluetooth then Connect. USB and Bluetooth both run setup and signing.");
    private final ProgressIndicator loading = new ProgressIndicator();
    private final Label loadingLabel = new Label("Loading…");
    private final Label bleLink = new Label("Bluetooth: not connected");
    private final Label deviceHalf = new Label("No seed in NVS");
    private final Label oracleHalf = new Label("No key share on this PC");
    private final Button rescanBtn = new Button("Scan Bluetooth");
    private final Button connectBtn = new Button("Connect Bluetooth");
    private final Button resetBtn = new Button("Reset Bluetooth");
    private final Button flashBtn = new Button("Flash firmware");
    private final Button fullFlashBtn = new Button("Full flash");
    private final Button unlockBtn = new Button("Set unlock");
    private final Button diceBtn = new Button("Roll dice");
    private final Button backupBtn = new Button("Backup");
    private final Button restoreBtn = new Button("Restore backup");
    private final Button wipeBtn = new Button("Wipe wallet");
    private volatile String devicePath;
    private volatile boolean detectAbandoned;
    private volatile javafx.concurrent.Service<Void> running;
    private boolean flashOffered;

    public BansheeSetupDialog() {
        DialogPane pane = getDialogPane();
        pane.getStyleClass().add("banshee-setup");
        AppServices.setStageIcon(pane.getScene().getWindow());
        setTitle("Set up Banshee");
        pane.getButtonTypes().addAll(ButtonType.CLOSE);
        setResultConverter(button -> null);
        pane.setMinWidth(980);
        pane.setPrefWidth(1100);
        pane.setPrefHeight(680);
        pane.getStylesheets().add(AppServices.class.getResource("general.css").toExternalForm());
        AppServices.moveToActiveWindowScreen(this);

        log.setEditable(false);
        log.setWrapText(true);
        log.setPrefHeight(240);
        status.setWrapText(true);
        loading.setPrefSize(18, 18);
        loading.setMinSize(18, 18);
        loading.setVisible(false);
        loading.setManaged(false);
        loadingLabel.getStyleClass().add("split-caption");
        loadingLabel.setVisible(false);
        loadingLabel.setManaged(false);
        HBox statusRow = new HBox(10, loading, loadingLabel, status);
        statusRow.setAlignment(javafx.geometry.Pos.CENTER_LEFT);
        HBox.setHgrow(status, Priority.ALWAYS);
        bleLink.getStyleClass().add("ble-link");
        deviceHalf.getStyleClass().add("split-miss");
        oracleHalf.getStyleClass().add("split-miss");

        offerFlash();
        rescanBtn.setOnAction(e -> run("Scan Bluetooth", this::scanBluetooth));
        connectBtn.setOnAction(e -> run("Connect Bluetooth", this::connectBluetooth));
        resetBtn.setOnAction(e -> resetBluetooth());
        flashBtn.setOnAction(e -> run("Flash", this::flash));
        fullFlashBtn.setOnAction(e -> run("Full flash", this::flashFull));
        unlockBtn.setOnAction(e -> run("Unlock", this::unlock));
        diceBtn.setOnAction(e -> run("Dice", this::dice));
        backupBtn.setOnAction(e -> run("Backup", this::backup));
        restoreBtn.setOnAction(e -> run("Restore", this::restore));
        wipeBtn.setOnAction(e -> run("Wipe", this::wipe));

        rescanBtn.setTooltip(new Tooltip("Scan for nearby Banshee boards and pick the ID shown on the screen"));
        connectBtn.setTooltip(new Tooltip("Optional. Connect over Bluetooth when the USB cable is not plugged in."));
        resetBtn.setTooltip(new Tooltip("Drop the Bluetooth helper immediately so you can scan a new board without waiting for a timeout. Use this if the board was unplugged or powered off."));
        fullFlashBtn.setTooltip(new Tooltip("USB: erase NVS (lock + wallet) and write bundled firmware. Gets a stuck lock screen off the device."));
        backupBtn.setTooltip(new Tooltip("Save a .banshee-backup from this board. Keep the file away from the paper 12 dice rolls."));
        restoreBtn.setTooltip(new Tooltip("Restore device, Restore oracle, or Restore both from a .banshee-backup and the 12 dice rolls"));
        wipeBtn.setTooltip(new Tooltip("Erase the seed on the device so you can roll or restore a different one"));

        Label deviceTitle = new Label("Device NVS");
        deviceTitle.getStyleClass().add("split-title");
        Label deviceHint = new Label("Wrapped seed half");
        deviceHint.getStyleClass().add("split-hint");
        VBox deviceCard = new VBox(6, deviceTitle, deviceHint, deviceHalf);
        deviceCard.getStyleClass().add("split-card");
        HBox.setHgrow(deviceCard, Priority.ALWAYS);

        Label plus = new Label("+");
        plus.getStyleClass().add("split-plus");

        Label oracleTitle = new Label("Light oracle");
        oracleTitle.getStyleClass().add("split-title");
        Label oracleHint = new Label("Key-share half");
        oracleHint.getStyleClass().add("split-hint");
        VBox oracleCard = new VBox(6, oracleTitle, oracleHint, oracleHalf);
        oracleCard.getStyleClass().add("split-card");
        HBox.setHgrow(oracleCard, Priority.ALWAYS);

        HBox split = new HBox(16, deviceCard, plus, oracleCard);
        split.setAlignment(javafx.geometry.Pos.CENTER);
        Label splitCaption = new Label("Neither half is the seed. Unlock combines them in RAM as HMAC(share, pin).");
        splitCaption.getStyleClass().add("split-caption");
        splitCaption.setWrapText(true);

        FlowPane buttons = new FlowPane(10, 10, rescanBtn, connectBtn, resetBtn, flashBtn, fullFlashBtn, unlockBtn, diceBtn, backupBtn, restoreBtn, wipeBtn);
        buttons.setPrefWrapLength(1040);
        VBox content = new VBox(12, statusRow, bleLink, split, splitCaption, buttons, log);
        content.setPadding(new Insets(16));
        pane.setContent(content);
        append("Plug the board in over USB, or Scan Bluetooth and pick the name that matches the ID on the screen. Bluetooth is optional. Then Set unlock. Roll dice or Restore — Light stores its key share when you press RIGHT to save.");
        append("Wallet ops use USB or Bluetooth. Flash firmware still needs USB.");
        Button close = (Button)pane.lookupButton(ButtonType.CLOSE);
        close.setText("Done");
        refreshLink();
        refreshSplit(null, null);
        run("Detect", this::detectUsb);
    }

    private void run(String title, ThrowingRunnable work) {
        Service<Void> prev = running;
        if(prev != null && prev.isRunning()) {
            detectAbandoned = true;
            prev.cancel();
        }
        detectAbandoned = false;
        setBusy(true, title);
        Service<Void> service = new Service<>() {
            @Override
            protected Task<Void> createTask() {
                return new Task<>() {
                    @Override
                    protected Void call() throws Exception {
                        if("Detect".equals(title)) {
                            runDetect(work);
                        } else {
                            work.run();
                        }
                        return null;
                    }
                };
            }
        };
        running = service;
        service.setOnSucceeded(e -> {
            if(running == service) {
                setBusy(false, title);
                syncConnectionUi();
            }
        });
        service.setOnCancelled(e -> {
            if(running == service) {
                setBusy(false, title);
                syncConnectionUi();
            }
        });
        service.setOnFailed(e -> {
            if(running == service) {
                setBusy(false, title);
                syncConnectionUi();
            }
            if(detectAbandoned || service.getState() == javafx.concurrent.Worker.State.CANCELLED) {
                return;
            }
            String msg = describe(service.getException(), title);
            Platform.runLater(() -> {
                if(!BansheeBle.connected()) {
                    status.setText(msg);
                }
                refreshLink();
            });
            append("Error: " + msg);
        });
        service.start();
    }

    private void runDetect(ThrowingRunnable work) throws Exception {
        ExecutorService exec = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "banshee-detect");
            t.setDaemon(true);
            return t;
        });
        Future<Void> future = exec.submit(() -> {
            work.run();
            return null;
        });
        try {
            future.get(DETECT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch(TimeoutException e) {
            detectAbandoned = true;
            future.cancel(true);
            Platform.runLater(() -> {
                if(BansheeBle.connected()) {
                    refreshLink();
                } else {
                    status.setText("No Banshee on USB. Scan or Reset Bluetooth, or plug in USB.");
                    refreshLink();
                }
            });
            append("USB detect timed out. Bluetooth is unchanged — Scan, Connect, or Reset Bluetooth, or plug in USB.");
        } catch(ExecutionException e) {
            Throwable cause = e.getCause();
            if(cause instanceof Exception ex) {
                throw ex;
            }
            throw e;
        } finally {
            exec.shutdownNow();
        }
    }

    private static String describe(Throwable err, String title) {
        while(err instanceof ExecutionException && err.getCause() != null) {
            err = err.getCause();
        }
        if(err == null) {
            return title + " failed";
        }
        String message = err.getMessage();
        return message == null || message.isBlank() ? err.getClass().getSimpleName() : message;
    }

    private void scanBluetooth() throws Exception {
        if(!BansheeBle.supported()) {
            throw new DeviceException("Bluetooth is only available in the Windows installer.");
        }
        detectAbandoned = false;
        BansheeBle.forget();
        devicePath = null;
        Platform.runLater(() -> {
            refreshLink();
            status.setText("Scanning for Banshee boards…");
        });
        append("Scanning Bluetooth. Match the name to the ID on the device screen.");
        java.util.List<BansheeBle.Advertised> found = BansheeBle.scan();
        if(detectAbandoned) {
            return;
        }
        if(found.isEmpty()) {
            throw new DeviceException("No Banshee Bluetooth device. Keep the board powered (USB power is enough), stay close, and turn computer Bluetooth on.");
        }
        BansheeBle.Advertised picked = pickDevice(found);
        if(picked == null || detectAbandoned) {
            append("Scan cancelled.");
            return;
        }
        BansheeBle.select(picked);
        devicePath = picked.path();
        append("Connecting to " + picked + "…");
        Platform.runLater(() -> status.setText("Connecting over Bluetooth…"));
        BansheeSerialProbe.sleep(800);
        BansheeBle.connectSelected();
        showDetected(picked.path(), true);
    }

    private void connectBluetooth() throws Exception {
        if(!BansheeBle.supported()) {
            throw new DeviceException("Bluetooth is only available in the Windows installer.");
        }
        if(!BansheeBle.hasTarget()) {
            scanBluetooth();
            return;
        }
        BansheeBle.Advertised picked = BansheeBle.selected();
        BansheeBle.invalidate();
        BansheeBle.select(picked);
        devicePath = picked.path();
        append("Connecting to " + picked + "…");
        Platform.runLater(() -> status.setText("Connecting over Bluetooth…"));
        BansheeBle.connectSelected();
        showDetected(picked.path(), true);
    }

    private void resetBluetooth() {
        detectAbandoned = true;
        BansheeBle.forget();
        devicePath = null;
        Service<Void> svc = running;
        if(svc != null) {
            svc.cancel();
        }
        setBusy(false, "Reset Bluetooth");
        status.setText("Bluetooth reset. Scan for a new board, or plug in USB.");
        refreshLink();
        append("Bluetooth reset. Helper dropped — Scan Bluetooth for a new board without waiting.");
    }

    private BansheeBle.Advertised pickDevice(java.util.List<BansheeBle.Advertised> found) throws Exception {
        if(found.size() == 1) {
            BansheeBle.Advertised only = found.get(0);
            Boolean ok = onFx(() -> {
                Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
                alert.initOwner(getOwner());
                alert.setTitle("Connect Banshee");
                alert.setHeaderText("Connect to " + only + "?");
                alert.getDialogPane().setContentText("This name should match Banshee- plus the ID on the device screen.");
                return alert.showAndWait().filter(b -> b == ButtonType.OK).isPresent();
            });
            return Boolean.TRUE.equals(ok) ? only : null;
        }
        return onFx(() -> {
            ChoiceDialog<BansheeBle.Advertised> dlg = new ChoiceDialog<>(found.get(0), found);
            dlg.initOwner(getOwner());
            dlg.setTitle("Scan Bluetooth");
            dlg.setHeaderText("Pick the board that matches the ID on the device screen.");
            dlg.setContentText("Device");
            return dlg.showAndWait().orElse(null);
        });
    }

    private void detectUsb() throws Exception {
        if(BansheeBle.connected() && BansheeBle.hasTarget()) {
            Platform.runLater(() -> status.setText("Loading… reusing Bluetooth."));
            append("Reusing Bluetooth to " + BansheeBle.selected() + ".");
            try {
                showDetected(BansheeBle.selected().path(), true);
                return;
            } catch(Exception e) {
                BansheeBle.invalidate();
                devicePath = null;
                append("Previous Bluetooth is gone (board unplugged or powered off). Reset or Scan, or plug USB.");
            }
        }
        Platform.runLater(() -> status.setText("Loading… looking for a Banshee."));
        append("Loading… looking for a Banshee.");
        String gate = BansheeSerialProbe.findGatePortPath();
        if(detectAbandoned) {
            return;
        }
        if(gate != null) {
            try {
                showDetected(gate, false);
                return;
            } catch(DeviceException e) {
                devicePath = null;
                if(BansheeSerialProbe.findBootloaderPortPath() == null) {
                    throw e;
                }
                append("USB detect failed: " + e.getMessage());
            }
        }
        if(BansheeSerialProbe.findBootloaderPortPath() != null) {
            Platform.runLater(() -> {
                offerFlash();
                status.setText("Download mode. Flash writes bundled " + BansheeFlash.bundledVersion()
                        + ". PEM flash updates app firmware only. If this fused board is blank, use Studio Full reflash with the original .pem.");
            });
            append("Bootloader only. Studio fused board: Flash → choose .pem (app update only). Blank screen after a bad flash: recover in Studio Full reflash, not here. New chip: Flash without a .pem.");
            return;
        }
        Platform.runLater(() -> {
            offerFlash();
            status.setText("Plug the board in over USB, or Scan Bluetooth then Connect. Match Banshee- plus the ID on the device screen.");
            refreshLink();
        });
        append("No Banshee on USB. Plug in the cable, or Scan Bluetooth then Connect Bluetooth.");
    }

    private void showDetected(String gate, boolean bluetooth) throws DeviceException {
        devicePath = gate;
        Platform.runLater(() -> status.setText("Talking to the board…"));
        append("Talking to the board.");
        BansheeInfo info = new Lark().withBanshee(gate, BansheeClient::getInfo);
        BansheeUnlockStatus unlock = info.asUnlockStatus();
        BansheeWalletStatus wallet = info.asWalletStatus();
        String ver = info.version() == null || info.version().isBlank() ? "?" : info.version();
        boolean sb = info.secureBoot();
        boolean enc = info.flashEnc();
        String lock = unlock.configured()
                ? (unlock.locked() ? "locked" : "unlocked")
                  + (unlock.oracle() ? ", oracle registered" : ", oracle not registered")
                  + (unlock.fails() > 0 ? ", " + unlock.remainingTries() : "")
                : "unlock not set";
        String link = bluetooth ? "Bluetooth connected" : "USB connected";
        Platform.runLater(() -> {
            if(enc) {
                hideFlash();
            } else {
                offerFlash();
            }
            String bundled = BansheeFlash.bundledVersion();
            status.setText("Firmware v" + ver
                    + " (Secure Boot " + (sb ? "on" : "off")
                    + (enc ? ", flash encryption on" : "")
                    + "). " + link + " — " + lock
                    + (info.deviceId().isBlank() ? "" : "  id " + info.deviceId())
                    + "."
                    + (enc ? " Flash encryption: update in Studio."
                            : " Flash still needs USB and can write bundled " + bundled + "."));
            refreshLink();
            refreshSplit(wallet, unlock);
        });
        append("Detected running firmware v" + ver + " secureBoot=" + (sb ? "1" : "0")
                + (enc ? " flashEnc=1" : "") + " " + lock
                + (bluetooth ? " over Bluetooth" : " over USB")
                + ". Bundled flash " + BansheeFlash.bundledVersion() + ".");
        if(wallet.ready() && !unlock.oracle()) {
            append("Seed is on the device but Light has no key share yet. Wipe then Roll dice or Restore to register the share while saving.");
        } else if(unlock.oracle() && !BansheeOracle.hasLocalShare()) {
            append("This board was set up on another Light. Restore the original .banshee-backup (and .pem) here — do not wipe. Then Unlock.");
        }
    }

    private void refreshLink() {
        String path = devicePath;
        if(path != null && !BansheeBle.isBlePath(path) && BansheeSerialProbe.portPresent(path)) {
            bleLink.setText("USB: connected (" + BansheeSerialProbe.normalizePortPath(path) + ")");
            bleLink.getStyleClass().setAll("ble-link", "split-ok");
            return;
        }
        if((BansheeBle.connected() || BansheeBle.alive()) && BansheeBle.hasTarget()) {
            bleLink.setText("Bluetooth: connected to " + BansheeBle.selected());
            bleLink.getStyleClass().setAll("ble-link", "split-ok");
            return;
        }
        if(BansheeBle.hasTarget()) {
            bleLink.setText("Bluetooth: " + BansheeBle.selected() + " selected — click Connect Bluetooth, or plug USB");
            bleLink.getStyleClass().setAll("ble-link");
            return;
        }
        bleLink.setText("Not connected — plug USB or Scan Bluetooth");
        bleLink.getStyleClass().setAll("ble-link");
    }

    private void refreshSplit(BansheeWalletStatus wallet, BansheeUnlockStatus unlock) {
        boolean nvsSeed = wallet != null && wallet.ready();
        boolean deviceOracle = unlock != null && unlock.oracle();
        boolean lightShare = BansheeOracle.hasLocalShare();
        deviceHalf.setText(nvsSeed ? "Wrapped seed is on the device" : "No seed in NVS");
        deviceHalf.getStyleClass().setAll(nvsSeed ? "split-ok" : "split-miss");
        if(lightShare && deviceOracle) {
            oracleHalf.setText("Key share is on this PC");
            oracleHalf.getStyleClass().setAll("split-ok");
        } else if(lightShare) {
            oracleHalf.setText("Key share is on this PC (board not registered yet)");
            oracleHalf.getStyleClass().setAll("split-ok");
        } else if(deviceOracle) {
            oracleHalf.setText("Board is registered, but this PC has no share");
            oracleHalf.getStyleClass().setAll("split-miss");
        } else {
            oracleHalf.setText("No key share on this PC");
            oracleHalf.getStyleClass().setAll("split-miss");
        }
    }

    private void refreshFromDevice() throws DeviceException {
        String path = devicePath;
        if(path == null || path.isBlank()) {
            Platform.runLater(() -> {
                refreshLink();
                refreshSplit(null, null);
            });
            return;
        }
        showDetected(path, BansheeBle.isBlePath(path));
    }

    private void syncConnectionUi() {
        Platform.runLater(() -> {
            refreshLink();
            if(BansheeBle.connected() && BansheeBle.hasTarget()) {
                String text = status.getText();
                if(text == null || text.isBlank() || text.startsWith("Loading") || text.startsWith("Connecting")
                        || text.startsWith("Talking") || text.startsWith("No Banshee")) {
                    status.setText("Bluetooth connected to " + BansheeBle.selected() + ".");
                }
            }
        });
    }

    private void flash() throws Exception {
        String app = BansheeSerialProbe.findAppPortPath();
        if(app != null) {
            devicePath = app;
            BansheeInfo info = new Lark().withBanshee(app, BansheeClient::getInfo);
            if(info.flashEnc()) {
                throw new DeviceException("This board has flash encryption. Use Banshee Studio with the flash-encryption key.");
            }
            String bundled = BansheeFlash.bundledVersion();
            if(!info.secureBoot()) {
                if(!confirmFlash("Update unsigned firmware to " + bundled + "?",
                        "This chip is not Secure Boot. Light will wait for download mode (hold LEFT, unplug, plug in) and write bundled "
                                + bundled + " including the bootloader.\n"
                                + "Cancel if this board already ran Studio Secure Boot.")) {
                    append("Flash cancelled.");
                    return;
                }
                Platform.runLater(() -> status.setText("Unplug, hold LEFT (BOOT), plug in. Waiting for bootloader…"));
                append("Writing bundled " + bundled + ". Hold LEFT, unplug 3s, plug in.");
                String path = BansheeFlash.flashUnsigned(this::append);
                if(path != null && !path.isBlank()) {
                    devicePath = path;
                }
                append("Flash complete. Firmware " + bundled + ".");
                return;
            }
            File pem = askPem();
            if(pem == null) {
                append("Flash cancelled — no .pem selected. Unlock / Import still work.");
                return;
            }
            if(!confirmFlash("Update app firmware to " + bundled + " on this Secure Boot board?",
                    "Signs bundled " + bundled + " with " + pem.getName() + " and rewrites both app slots.\n"
                            + "The bootloader, partition table and your wallet are left alone.\n\n"
                            + "You will be asked to hold LEFT and replug to enter download mode.")) {
                append("Flash cancelled.");
                return;
            }
            Platform.runLater(() -> status.setText("Unplug, hold LEFT (BOOT), plug in. Waiting for bootloader…"));
            append("Signing update with " + pem.getName() + ". Hold LEFT, unplug 3s, plug in.");
            String path = BansheeFlash.flashSigned(pem.toPath(), this::append);
            if(path != null && !path.isBlank()) {
                devicePath = path;
            }
            append("Signed update complete. Firmware " + BansheeFlash.bundledVersion() + ".");
            return;
        }
        File pem = askPemOrUnsigned();
        if(pem == ASK_CANCELLED) {
            append("Flash cancelled.");
            return;
        }
        if(pem != null) {
            if(!confirmFlash("Write signed app firmware " + BansheeFlash.bundledVersion() + " to this board?",
                    "Signs bundled " + BansheeFlash.bundledVersion() + " with " + pem.getName() + " and rewrites both app slots.\n"
                            + "The bootloader and partition table stay exactly as Studio wrote them.")) {
                append("Flash cancelled.");
                return;
            }
            append("Signed app update with " + pem.getName() + " (bootloader not rewritten)…");
            String path = BansheeFlash.flashSigned(pem.toPath(), this::append);
            if(path != null && !path.isBlank()) {
                devicePath = path;
            }
            append("Signed update complete. Firmware " + BansheeFlash.bundledVersion() + ".");
            return;
        }
        if(!confirmNewUnfusedBoard()) {
            append("Flash cancelled.");
            return;
        }
        append("Looking for bootloader PID 1001…");
        String path = BansheeFlash.flashUnsigned(this::append);
        if(path != null && !path.isBlank()) {
            devicePath = path;
        }
        append("Flash complete. Firmware " + BansheeFlash.bundledVersion() + ".");
    }

    private void flashFull() throws Exception {
        String app = BansheeSerialProbe.findAppPortPath();
        if(app != null) {
            BansheeInfo info = new Lark().withBanshee(app, BansheeClient::getInfo);
            if(info.flashEnc()) {
                throw new DeviceException("This board has flash encryption. Use Banshee Studio with the flash-encryption key.");
            }
            if(info.secureBoot()) {
                File pem = askPem();
                if(pem == null) {
                    append("Full flash cancelled — no .pem selected.");
                    return;
                }
                if(!confirmFlash("Full flash " + BansheeFlash.bundledVersion() + " and erase lock + wallet?",
                        "Erases NVS (unlock sequence and any seed) then writes signed app firmware "
                                + BansheeFlash.bundledVersion() + " with " + pem.getName() + ".\n"
                                + "The Studio bootloader stays. This is how you leave a stuck lock screen.\n\n"
                                + "Hold LEFT and replug for download mode.")) {
                    append("Full flash cancelled.");
                    return;
                }
                Platform.runLater(() -> status.setText("Unplug, hold LEFT (BOOT), plug in. Waiting for bootloader…"));
                String path = BansheeFlash.flashFull(pem.toPath(), this::append);
                if(path != null && !path.isBlank()) {
                    devicePath = path;
                }
                append("Full flash complete. Lock and wallet NVS were erased. Firmware " + BansheeFlash.bundledVersion() + ".");
                return;
            }
            if(!confirmFlash("Full flash unsigned " + BansheeFlash.bundledVersion() + " and erase the chip?",
                    "Erases the entire flash including lock and wallet, then writes unsigned bundled "
                            + BansheeFlash.bundledVersion() + ".\n"
                            + "Cancel if this board already ran Studio Secure Boot.")) {
                append("Full flash cancelled.");
                return;
            }
            Platform.runLater(() -> status.setText("Unplug, hold LEFT (BOOT), plug in. Waiting for bootloader…"));
            String path = BansheeFlash.flashFull(null, this::append);
            if(path != null && !path.isBlank()) {
                devicePath = path;
            }
            append("Full flash complete. Firmware " + BansheeFlash.bundledVersion() + ".");
            return;
        }
        File pem = askPemOrUnsigned();
        if(pem == ASK_CANCELLED) {
            append("Full flash cancelled.");
            return;
        }
        if(pem != null) {
            if(!confirmFlash("Full flash signed " + BansheeFlash.bundledVersion() + " and erase lock + wallet?",
                    "Erases NVS then writes signed app firmware with " + pem.getName() + ".")) {
                append("Full flash cancelled.");
                return;
            }
            String path = BansheeFlash.flashFull(pem.toPath(), this::append);
            if(path != null && !path.isBlank()) {
                devicePath = path;
            }
            append("Full flash complete. Firmware " + BansheeFlash.bundledVersion() + ".");
            return;
        }
        if(!confirmFlash("Full flash only a brand-new chip that has never had Studio Secure Boot.",
                "Erases the chip and writes unsigned bundled firmware. A fused board will not boot.")) {
            append("Full flash cancelled.");
            return;
        }
        String path = BansheeFlash.flashFull(null, this::append);
        if(path != null && !path.isBlank()) {
            devicePath = path;
        }
        append("Full flash complete. Firmware " + BansheeFlash.bundledVersion() + ".");
    }

    private boolean confirmNewUnfusedBoard() throws Exception {
        return confirmFlash("Flash only a brand-new chip that has never had Studio Secure Boot.",
                "If this board already ran Banshee Wallet or Studio, Cancel. Light's unsigned firmware will not boot on a fused chip (blank screen, stuck in bootloader).");
    }

    /** Last gate before anything is written to the chip. No flash path may skip this. */
    private boolean confirmFlash(String header, String detail) throws Exception {
        Boolean ok = onFx(() -> {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.initOwner(getOwner());
            alert.setTitle("Flash firmware");
            alert.setHeaderText(header);
            alert.getDialogPane().setContentText(detail);
            ButtonType flashNow = new ButtonType("Flash now", ButtonBar.ButtonData.OK_DONE);
            ButtonType cancel = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
            alert.getButtonTypes().setAll(cancel, flashNow);
            return alert.showAndWait().filter(b -> b == flashNow).isPresent();
        });
        return Boolean.TRUE.equals(ok);
    }

    private void unlock() throws Exception {
        String path = requireDevice();
        String url = BansheeOracle.DEVICE_URL;
        String pubkey = BansheeOracle.pubkey();
        BansheeUnlockStatus st = new Lark().withBanshee(path, BansheeClient::unlockStatus);
        showDetected(path, BansheeBle.isBlePath(path));
        if(st.fails() > 0) {
            append(st.remainingTries() + ".");
        }
        if(st.configured() && st.oracle() && st.locked()) {
            append("Enter the sequence on the device. Light's oracle reconstructs the wrap key over USB or Bluetooth.");
            BansheeUnlockStatus after = new Lark().withBanshee(path, BansheeClient::unlockOracle);
            append("Unlocked. " + after.remainingTries() + ".");
            refreshFromDevice();
            return;
        }
        if(st.configured() && st.oracle()) {
            append("Unlock sequence already registered with Light. " + st.remainingTries() + ".");
            return;
        }
        if(st.configured() && st.locked()) {
            append("Lock is stored on the device. Enter the sequence on the buttons. Oracle is only used when a seed wrap is registered.");
            append("Stuck on the lock screen after 0.1.50: use Full flash over USB to erase NVS.");
            return;
        }
        if(st.configured()) {
            BansheeWalletStatus wallet = new Lark().withBanshee(path, BansheeClient::walletStatus);
            if(wallet.ready() && !st.oracle()) {
                append("Enter the sequence on the device. Light stores its key share and wraps the seed already on the board.");
                BansheeUnlockStatus after = new Lark().withBanshee(path, BansheeClient::unlockOracle);
                append("Key share saved. Board is restarting…");
                reconnectAfterRestart(path);
                append("Oracle registered. " + after.remainingTries() + ".");
                return;
            }
            append("Unlock already set on the device. Roll dice or Restore to store Light's key share. " + st.remainingTries() + ".");
            return;
        }
        append("Enter a 6–12 press L/R sequence on the device, pause, then enter it again to confirm.");
        BansheeUnlockStatus after = new Lark().withBanshee(path, client -> client.setOracleAndUnlock(url, pubkey));
        append("Unlock sequence saved. Board is restarting…");
        reconnectAfterRestart(path);
        append("Unlock sequence saved on the device. " + after.remainingTries() + ".");
    }

    private void reconnectAfterRestart(String path) {
        boolean ble = BansheeBle.isBlePath(path);
        BansheeBle.invalidate();
        if(!ble) {
            BansheeSerialProbe.invalidate();
        }
        Platform.runLater(() -> status.setText("Board restarting…"));
        BansheeSerialProbe.sleep(2500);
        for(int i = 0; i < 8; i++) {
            try {
                String usb = BansheeSerialProbe.findGatePortPath();
                if(usb != null) {
                    showDetected(usb, false);
                    return;
                }
                if(ble && BansheeBle.hasTarget()) {
                    BansheeBle.connectSelected();
                    showDetected(BansheeBle.selected().path(), true);
                    return;
                }
            } catch(Exception e) {
                BansheeBle.invalidate();
            }
            BansheeSerialProbe.sleep(1500);
        }
        append(ble
                ? "Waiting after restart. Plug USB or click Connect Bluetooth."
                : "Waiting for USB after restart. Unplug and replug if needed.");
        Platform.runLater(this::refreshLink);
    }

    private void dice() throws Exception {
        String path = requireDevice();
        BansheeWalletStatus wallet = new Lark().withBanshee(path, BansheeClient::walletStatus);
        if(wallet.ready()) {
            append("Wallet already on device. Fingerprint " + wallet.fingerprint());
            return;
        }
        BansheeUnlockStatus unlock = new Lark().withBanshee(path, BansheeClient::unlockStatus);
        if(!unlock.configured()) {
            throw new DeviceException("Set unlock first, then Roll dice.");
        }
        if(unlock.fails() > 0) {
            append(unlock.remainingTries() + ".");
        }
        if(unlock.locked()) {
            throw new DeviceException("Unlock on the device first, then Roll dice.");
        }
        append("Rolling 100 EFF words on device. Dice become the BIP39 passphrase (25th word); the 24-word seed stays on the chip. After the roll, write down the 12 five-digit dice rolls on the screen (3 pages), then press RIGHT to save.");
        BansheeClient.BansheeDiceResult result = new Lark().generateBansheeDiceWallet(path, this::append);
        append("Wallet saved. Fingerprint " + result.fingerprint() + ". Board is restarting…");
        reconnectAfterRestart(path);
    }

    private enum RestoreTarget {
        DEVICE, ORACLE, BOTH
    }

    private void backup() throws Exception {
        String path = requireDevice();
        BansheeWalletStatus wallet = new Lark().withBanshee(path, BansheeClient::walletStatus);
        if(!wallet.ready()) {
            throw new DeviceException("No wallet on device to back up");
        }
        append("Press RIGHT on the device to export the clone blob…");
        String payload = new Lark().withBanshee(path, BansheeClient::cloneExport);
        String wrapHex;
        try {
            wrapHex = new Lark().withBanshee(path, BansheeClient::backupWrap);
        } catch(DeviceException e) {
            String msg = e.getMessage() == null ? "" : e.getMessage();
            if(msg.contains("backup_wrap_unavailable") || msg.contains("unknown_cmd")) {
                throw new DeviceException("This board has no backup wrap key. Create the wallet on firmware that shows the 12 dice rolls, or Restore device/both with those rolls first.");
            }
            throw e;
        }
        byte[] wrapKey = BansheeBackupFile.wrapKeyFromHex(wrapHex);
        BansheeOracle.Snapshot oracle = BansheeOracle.snapshot();
        String json = BansheeBackupFile.seal(wallet.fingerprint(), payload, oracle, wrapKey);
        File file = onFx(() -> {
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Save Banshee backup");
            chooser.setInitialFileName("banshee-backup-" + wallet.fingerprint() + ".banshee-backup");
            return chooser.showSaveDialog(getOwner());
        });
        if(file != null) {
            Files.writeString(file.toPath(), json);
            append("Saved " + file.getName() + ". Keep this file away from the paper 12 dice rolls. Restore types those rolls.");
        }
    }

    private void restore() throws Exception {
        RestoreTarget target = askRestoreTarget();
        if(target == null) {
            append("Restore cancelled.");
            return;
        }
        String path = target == RestoreTarget.ORACLE ? optionalDevicePath() : requireDevice();
        File file = askOpenBackup();
        if(file == null) {
            return;
        }
        String text = Files.readString(file.toPath());
        int version = BansheeBackupFile.peekVersion(text);
        BansheeBackupFile.Opened opened;
        char[] sequence = null;
        char[] words = null;
        if(version == BansheeBackupFile.VERSION || version == BansheeBackupFile.PBKDF2_WORDS_VERSION) {
            words = askRecoveryWords("Enter the 12 five-digit dice rolls shown on the device after the roll");
            if(words == null) {
                append("Restore cancelled.");
                return;
            }
            opened = BansheeBackupFile.openWords(text, words);
        } else if(version == BansheeBackupFile.PASSPHRASE_VERSION) {
            char[] pass = askPassphrase("Backup passphrase");
            if(pass == null) {
                return;
            }
            opened = BansheeBackupFile.open(text, pass);
        } else {
            File pemFile = askRestorePem();
            if(pemFile == null) {
                append("Restore cancelled — no .pem selected.");
                return;
            }
            sequence = askUnlockSequence("Enter the original unlock sequence to open this backup");
            if(sequence == null) {
                append("Restore cancelled.");
                return;
            }
            opened = BansheeBackupFile.openPem(text, Files.readString(pemFile.toPath()), sequence);
        }
        try {
            String backupPub = opened.oracle() != null && opened.oracle().key() != null ? opened.oracle().key().pub() : null;
            if(target == RestoreTarget.ORACLE || target == RestoreTarget.BOTH) {
                enrollOracleFromBackup(opened);
            }
            if(target == RestoreTarget.DEVICE || target == RestoreTarget.BOTH) {
                restoreDeviceFromBackup(path, opened, backupPub);
                persistBackupWrap(path, words);
            } else if(path != null) {
                bindOracleIfMatching(path, opened, backupPub);
            }
        } finally {
            if(sequence != null) {
                Arrays.fill(sequence, '\0');
            }
            if(words != null) {
                Arrays.fill(words, '\0');
            }
        }
    }

    private void enrollOracleFromBackup(BansheeBackupFile.Opened opened) throws Exception {
        if(opened.oracle() == null || !opened.oracle().present()) {
            throw new DeviceException("This backup has no Light oracle config. Create a new backup in Banshee Light.");
        }
        byte[] share = BansheeOracle.exportShare(opened.oracle());
        if(share == null) {
            throw new DeviceException("This backup has no Light oracle share. Create a new backup on the original Light.");
        }
        BansheeOracle.appendSnapshot(opened.oracle(), true);
        BansheeOracle.enrollWallet(opened.oracle().key(), share);
        append("This Light now has the original oracle key and share. Unlock on the board with its screen sequence, then import the keystore.");
    }

    private void restoreDeviceFromBackup(String path, BansheeBackupFile.Opened opened, String backupPub) throws Exception {
        BansheeWalletStatus current = new Lark().withBanshee(path, BansheeClient::walletStatus);
        if(current.ready()) {
            if(!opened.fingerprint().isBlank() && !opened.fingerprint().equalsIgnoreCase(current.fingerprint())) {
                throw new DeviceException("This board already has a different wallet (device "
                        + current.fingerprint() + ", backup " + opened.fingerprint()
                        + "). Wipe it, set an unlock sequence, then Restore device.");
            }
            if(backupPub != null && !backupPub.isBlank()) {
                new Lark().withBanshee(path, client -> client.setOracle(BansheeOracle.DEVICE_URL, backupPub));
            }
            append("Board already has this wallet. Unlock with this board's screen sequence.");
            refreshFromDevice();
            return;
        }
        append("Press RIGHT to import. If the board asks for the sequence, enter this board's screen unlock — that wraps the seed with this Light.");
        String pub = backupPub;
        BansheeWalletStatus imported = new Lark().withBanshee(path, client -> client.cloneImport(opened.payload(), pub));
        if(!opened.fingerprint().isBlank() && !opened.fingerprint().equalsIgnoreCase(imported.fingerprint())) {
            throw new DeviceException("Fingerprint mismatch (backup " + opened.fingerprint() + " vs device " + imported.fingerprint() + ")");
        }
        append("Restored fingerprint " + imported.fingerprint() + ". Board is restarting…");
        reconnectAfterRestart(path);
    }

    private void bindOracleIfMatching(String path, BansheeBackupFile.Opened opened, String backupPub) throws Exception {
        BansheeWalletStatus current = new Lark().withBanshee(path, BansheeClient::walletStatus);
        if(!current.ready()) {
            append("Oracle is on this Light. Use Restore device to put the seed on an empty board.");
            return;
        }
        if(!opened.fingerprint().isBlank() && !opened.fingerprint().equalsIgnoreCase(current.fingerprint())) {
            append("This Light has the oracle. The plugged-in board is a different wallet — leave it, or Wipe and Restore device.");
            return;
        }
        if(backupPub != null && !backupPub.isBlank()) {
            new Lark().withBanshee(path, client -> client.setOracle(BansheeOracle.DEVICE_URL, backupPub));
        }
        append("Board already has this wallet. Unlock with this board's screen sequence.");
        refreshFromDevice();
    }

    private void persistBackupWrap(String path, char[] words) {
        if(path == null || words == null) {
            return;
        }
        try {
            String hex = BansheeBackupFile.wrapKeyHex(BansheeBackupFile.wrapKeyFromWords(BansheeBackupFile.normalizeRecoveryWords(words)));
            new Lark().withBanshee(path, client -> {
                client.backupWrapSet(hex);
                return true;
            });
            append("This board can Backup without typing the 12 dice rolls.");
        } catch(Exception e) {
            append("Could not store backup wrap on the board: " + e.getMessage());
        }
    }

    private void wipe() throws Exception {
        String path = requireDevice();
        BansheeWalletStatus wallet = new Lark().withBanshee(path, BansheeClient::walletStatus);
        if(!wallet.ready()) {
            append("No wallet on device. Nothing to wipe.");
            return;
        }
        if(!confirmWipe(wallet.fingerprint())) {
            append("Wipe cancelled.");
            return;
        }
        append("Press RIGHT on the device to confirm the wipe. LEFT rejects.");
        BansheeWalletStatus after = new Lark().withBanshee(path, BansheeClient::walletDelete);
        if(after.ready()) {
            throw new DeviceException("Device still reports a wallet after wipe");
        }
        append("Wallet erased. Roll dice or restore a backup to put a new seed on the device.");
        refreshFromDevice();
    }

    private boolean confirmWipe(String fingerprint) throws Exception {
        String typed = onFx(() -> {
            TextInputDialog dlg = new TextInputDialog();
            dlg.initOwner(getOwner());
            dlg.setTitle("Wipe wallet");
            dlg.setHeaderText("Erase the seed on this device (fingerprint " + fingerprint + ")?");
            dlg.getDialogPane().setContentText(
                    "Back up first if you may want this seed again — Backup saves a file; keep it away from the paper 12 dice rolls.\n"
                            + "Without one, any coins on this seed are gone for good.\n\n"
                            + "Type WIPE to confirm");
            return dlg.showAndWait().orElse(null);
        });
        if(typed == null) {
            return false;
        }
        if(!"WIPE".equals(typed.trim().toUpperCase())) {
            append("Wipe not confirmed. Coins are unrecoverable without a backup, so the word must match.");
            return false;
        }
        return true;
    }

    private String requireDevice() throws DeviceException {
        String usb = BansheeSerialProbe.findGatePortPath();
        if(usb != null && !usb.isBlank()) {
            devicePath = usb;
            return usb;
        }
        String cached = devicePath;
        if(cached != null && !cached.isBlank() && !BansheeBle.isBlePath(cached) && BansheeSerialProbe.portPresent(cached)) {
            return cached;
        }
        if(BansheeBle.connected() && BansheeBle.hasTarget()) {
            String ble = BansheeBle.pathOf(BansheeBle.selected());
            devicePath = ble;
            return ble;
        }
        if(cached != null && BansheeBle.isBlePath(cached)) {
            BansheeBle.selectFromPath(cached);
            return cached;
        }
        devicePath = null;
        String gate = BansheeSerialProbe.findPreferredPath();
        if(gate == null) {
            if(BansheeSerialProbe.findBootloaderPortPath() != null) {
                throw new DeviceException(BOOTLOADER_ONLY);
            }
            throw new DeviceException("Plug the Banshee in over USB, or Scan Bluetooth then Connect.");
        }
        if(!BansheeBle.isBlePath(gate) && gate.equals(BansheeSerialProbe.findBootloaderPortPath())) {
            throw new DeviceException(BOOTLOADER_ONLY);
        }
        devicePath = gate;
        return devicePath;
    }

    private char[] askPassphrase(String header) throws Exception {
        return onFx(() -> {
            Dialog<String> dlg = new Dialog<>();
            dlg.initOwner(getOwner());
            dlg.setTitle("Backup passphrase");
            dlg.setHeaderText(header);
            PasswordField field = new PasswordField();
            dlg.getDialogPane().setContent(field);
            dlg.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);
            dlg.setResultConverter(btn -> btn.getButtonData() == ButtonBar.ButtonData.OK_DONE ? field.getText() : null);
            Optional<String> result = dlg.showAndWait();
            return result.filter(s -> !s.isBlank()).map(String::toCharArray).orElse(null);
        });
    }

    private char[] askRecoveryWords(String header) throws Exception {
        return onFx(() -> {
            Dialog<String> dlg = new Dialog<>();
            dlg.initOwner(getOwner());
            dlg.setTitle("Backup rolls");
            dlg.setHeaderText(header);
            TextArea field = new TextArea();
            field.setPrefRowCount(4);
            field.setWrapText(true);
            Label hint = new Label("Type the 12 five-digit rolls in order, separated by spaces.");
            hint.getStyleClass().add("split-hint");
            VBox box = new VBox(8, hint, field);
            dlg.getDialogPane().setContent(box);
            dlg.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);
            dlg.setResultConverter(btn -> btn.getButtonData() == ButtonBar.ButtonData.OK_DONE ? field.getText() : null);
            Optional<String> result = dlg.showAndWait();
            if(result.isEmpty() || result.get().isBlank()) {
                return null;
            }
            try {
                String normalized = BansheeBackupFile.normalizeRecoveryWords(result.get().toCharArray());
                BansheeBackupFile.checkRecoveryWords(normalized);
                return normalized.toCharArray();
            } catch(IllegalArgumentException e) {
                Alert alert = new Alert(Alert.AlertType.ERROR);
                alert.initOwner(getOwner());
                alert.setTitle("Backup rolls");
                alert.setHeaderText("Could not use those rolls");
                alert.setContentText(e.getMessage());
                alert.showAndWait();
                return null;
            }
        });
    }

    private char[] askUnlockSequence(String header) throws Exception {
        return onFx(() -> {
            Dialog<String> dlg = new Dialog<>();
            dlg.initOwner(getOwner());
            dlg.setTitle("Unlock sequence");
            dlg.setHeaderText(header);
            PasswordField field = new PasswordField();
            Label hint = new Label("Type 6–12 L and R keys (the same sequence as on the device).");
            hint.getStyleClass().add("split-hint");
            VBox box = new VBox(8, hint, field);
            dlg.getDialogPane().setContent(box);
            dlg.getDialogPane().getButtonTypes().addAll(ButtonType.OK, ButtonType.CANCEL);
            dlg.setResultConverter(btn -> btn.getButtonData() == ButtonBar.ButtonData.OK_DONE ? field.getText() : null);
            Optional<String> result = dlg.showAndWait();
            if(result.isEmpty() || result.get().isBlank()) {
                return null;
            }
            try {
                String seq = BansheeBackupFile.normalizeSequence(result.get().toCharArray());
                BansheeBackupFile.checkSequence(seq);
                return seq.toCharArray();
            } catch(IllegalArgumentException e) {
                Alert alert = new Alert(Alert.AlertType.ERROR);
                alert.initOwner(getOwner());
                alert.setTitle("Unlock sequence");
                alert.setHeaderText("Could not use that sequence");
                alert.setContentText(e.getMessage());
                alert.showAndWait();
                return null;
            }
        });
    }

    private static final File ASK_CANCELLED = new File(".");

    private File askOpenBackup() throws Exception {
        return onFx(() -> {
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Open Banshee backup");
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Banshee backup", "*.banshee-backup", "*.json"));
            return chooser.showOpenDialog(getOwner());
        });
    }

    private <T> T onFx(java.util.function.Supplier<T> work) throws Exception {
        if(Platform.isFxApplicationThread()) {
            return work.get();
        }
        CompletableFuture<T> done = new CompletableFuture<>();
        Platform.runLater(() -> {
            try {
                done.complete(work.get());
            } catch(Throwable t) {
                done.completeExceptionally(t);
            }
        });
        try {
            return done.get(DIALOG_TIMEOUT_MINUTES, TimeUnit.MINUTES);
        } catch(TimeoutException e) {
            done.cancel(true);
            throw new DeviceException("Timed out waiting for the dialog. Close it and try again.");
        }
    }

    private File askPemOrCreate() throws Exception {
        String choice = onFx(() -> {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.initOwner(getOwner());
            alert.setTitle("Backup signing key");
            alert.setHeaderText("Create a new .pem, or choose one you already have?");
            alert.getDialogPane().setContentText(
                    "First backup: Create .pem, store it offline with the backup file. Restore needs that same file. "
                            + "If you already flashed with a Studio .pem, choose that file instead.");
            ButtonType create = new ButtonType("Create .pem", ButtonBar.ButtonData.LEFT);
            ButtonType choose = new ButtonType("Choose .pem", ButtonBar.ButtonData.OK_DONE);
            ButtonType cancel = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
            alert.getButtonTypes().setAll(cancel, create, choose);
            ButtonType picked = alert.showAndWait().orElse(cancel);
            if(picked == create) {
                return "create";
            }
            if(picked == choose) {
                return "choose";
            }
            return null;
        });
        if(choice == null) {
            return null;
        }
        if("choose".equals(choice)) {
            return askPem("Backup signing key");
        }
        append("Creating RSA-3072 signing key…");
        String pem = EspSecureBootV2.generateSigningKeyPem();
        File dest = onFx(() -> {
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Save backup signing key");
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PEM key", "*.pem"));
            chooser.setInitialFileName("banshee-backup-signing-key.pem");
            return chooser.showSaveDialog(getOwner());
        });
        if(dest == null) {
            return null;
        }
        Files.writeString(dest.toPath(), pem);
        append("Saved " + dest.getName() + ". Keep this file — it is the only way to open the backup.");
        return dest;
    }

    private File askPem() throws Exception {
        return askPem("Studio Secure Boot signing key");
    }

    private File askPem(String title) throws Exception {
        return onFx(() -> {
            FileChooser chooser = new FileChooser();
            chooser.setTitle(title);
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PEM key", "*.pem"));
            return chooser.showOpenDialog(getOwner());
        });
    }

    private RestoreTarget askRestoreTarget() throws Exception {
        return onFx(() -> {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.initOwner(getOwner());
            alert.setTitle("Restore backup");
            alert.setHeaderText("What do you want to restore?");
            alert.getDialogPane().setContentText(
                    "You will choose the backup file, then enter the 12 five-digit dice rolls shown on the device after the roll.\n\n"
                            + "Restore device: put the seed on an empty board. This Light should already have the oracle.\n"
                            + "Restore oracle: put Light's key share on this computer. The board should already have this wallet.\n"
                            + "Restore both: new board and this Light from the same file.\n\n"
                            + "Different wallet on this board: Wipe first, then Restore device or Restore both.\n"
                            + "Older backups still need the .pem (and unlock sequence for v5).");
            ButtonType both = new ButtonType("Restore both", ButtonBar.ButtonData.OK_DONE);
            ButtonType device = new ButtonType("Restore device", ButtonBar.ButtonData.LEFT);
            ButtonType oracle = new ButtonType("Restore oracle", ButtonBar.ButtonData.RIGHT);
            ButtonType cancel = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
            alert.getButtonTypes().setAll(cancel, oracle, device, both);
            return alert.showAndWait().map(b -> {
                if(b == both) {
                    return RestoreTarget.BOTH;
                }
                if(b == device) {
                    return RestoreTarget.DEVICE;
                }
                if(b == oracle) {
                    return RestoreTarget.ORACLE;
                }
                return null;
            }).orElse(null);
        });
    }

    private String optionalDevicePath() {
        try {
            return requireDevice();
        } catch(DeviceException e) {
            return null;
        }
    }

    private File askRestorePem() throws Exception {
        Boolean ok = onFx(() -> {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.initOwner(getOwner());
            alert.setTitle("Restore signing key");
            alert.setHeaderText("Choose the same .pem used when this backup was created");
            alert.getDialogPane().setContentText(
                    "This is the backup signing key (banshee-backup-signing-key.pem), not a new file and not the Secure Boot flash key unless you chose that .pem at backup.");
            ButtonType choose = new ButtonType("Choose .pem", ButtonBar.ButtonData.OK_DONE);
            ButtonType cancel = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
            alert.getButtonTypes().setAll(cancel, choose);
            return alert.showAndWait().filter(b -> b == choose).isPresent();
        });
        if(!Boolean.TRUE.equals(ok)) {
            return null;
        }
        return askPem("Backup signing key");
    }

    private File askPemOrUnsigned() throws Exception {
        return onFx(() -> {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.initOwner(getOwner());
            alert.setTitle("Flash firmware");
            alert.setHeaderText("Studio Secure Boot board or new unfused chip?");
            alert.getDialogPane().setContentText("Choose the original Studio .pem to update app firmware only (bootloader stays). Unsigned flash is only for a brand-new chip that has never had Secure Boot. A blank fused board must be recovered in Studio Full reflash.");
            ButtonType pem = new ButtonType("Choose .pem", ButtonBar.ButtonData.OK_DONE);
            ButtonType unfused = new ButtonType("New unfused chip", ButtonBar.ButtonData.LEFT);
            ButtonType cancel = new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE);
            alert.getButtonTypes().setAll(cancel, unfused, pem);
            java.util.Optional<ButtonType> result = alert.showAndWait();
            if(result.isEmpty() || result.get() == cancel) {
                return ASK_CANCELLED;
            }
            if(result.get() == unfused) {
                return null;
            }
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Studio Secure Boot signing key");
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("PEM key", "*.pem"));
            File file = chooser.showOpenDialog(getOwner());
            return file == null ? ASK_CANCELLED : file;
        });
    }

    private void hideFlash() {
        flashOffered = false;
        flashBtn.setVisible(false);
        flashBtn.setManaged(false);
        flashBtn.setDisable(true);
    }

    private void offerFlash() {
        flashOffered = true;
        flashBtn.setVisible(true);
        flashBtn.setManaged(true);
        flashBtn.setDisable(false);
    }

    private void setBusy(boolean busy, String title) {
        Platform.runLater(() -> {
            loading.setVisible(busy);
            loading.setManaged(busy);
            loadingLabel.setVisible(busy);
            loadingLabel.setManaged(busy);
            rescanBtn.setDisable(busy && "Scan Bluetooth".equals(title));
            connectBtn.setDisable(busy);
            resetBtn.setDisable(false);
            flashBtn.setDisable(busy || !flashOffered);
            fullFlashBtn.setDisable(busy);
            unlockBtn.setDisable(busy);
            diceBtn.setDisable(busy);
            backupBtn.setDisable(busy);
            restoreBtn.setDisable(busy);
            wipeBtn.setDisable(busy);
        });
    }

    private void append(String line) {
        if(Platform.isFxApplicationThread()) {
            log.appendText(line + "\n");
        } else {
            Platform.runLater(() -> log.appendText(line + "\n"));
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
