// Banshee additions to Lark. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import com.fazecast.jSerialComm.SerialPort;
import com.sparrowwallet.drongo.*;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.policy.PolicyType;
import com.sparrowwallet.drongo.protocol.ScriptType;
import com.sparrowwallet.drongo.psbt.PSBT;
import com.sparrowwallet.drongo.psbt.PSBTParseException;
import com.sparrowwallet.drongo.wallet.WalletModel;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Lark client for the Banshee hardware wallet (LilyGo T-Display S3).
 */
public class BansheeClient extends HardwareClient {
    public static final List<DeviceId> BANSHEE_DEVICE_IDS = List.of(
            new DeviceId(0x303a, 0xb05e));

    private final SerialPort serialPort;
    private final String path;
    private final String network;
    private String masterFingerprint;

    public BansheeClient(SerialPort serialPort) {
        this.serialPort = serialPort;
        this.path = serialPort.getSystemPortPath();
        this.network = Network.getCanonical().getName();
    }

    public BansheeClient(String path) {
        this.serialPort = null;
        this.path = path;
        this.network = Network.getCanonical().getName();
    }

    private BansheeGate openGate() throws DeviceException {
        if(serialPort != null) {
            return new BansheeGate(serialPort, network);
        }
        return new BansheeGate(path, network);
    }

    @Override
    void initializeMasterFingerprint() throws DeviceException {
        try(BansheeGate gate = openGate()) {
            this.masterFingerprint = gate.getFingerprint();
        }
    }

    @Override
    ExtendedKey getPubKeyAtPath(String path) throws DeviceException {
        try(BansheeGate gate = openGate()) {
            ensureOracleUnlocked(gate);
            return ExtendedKey.fromDescriptor(gate.getXpub(path));
        }
    }

    @Override
    PSBT signTransaction(PSBT psbt) throws DeviceException {
        try(BansheeGate gate = openGate()) {
            ensureOracleUnlocked(gate);
            byte[] psbtBytes = psbt.getForExport().serialize();
            String b64 = Base64.getEncoder().encodeToString(psbtBytes);
            String signedB64 = gate.signPsbt(b64);
            PSBT devicePsbt = parseDeviceSignedPsbt(signedB64);
            if(devicePsbt.getPsbtInputs().size() != psbt.getPsbtInputs().size()) {
                throw new DeviceException("Banshee signed PSBT is incomplete (got "
                        + devicePsbt.getPsbtInputs().size() + " inputs, expected "
                        + psbt.getPsbtInputs().size() + ")");
            }
            boolean anySig = devicePsbt.getPsbtInputs().stream()
                    .anyMatch(input -> !input.getPartialSignatures().isEmpty());
            if(!anySig) {
                throw new DeviceException("Banshee returned a PSBT with no signatures");
            }
            // uBitcoin re-serializes only the unsigned tx + partial sigs (drops UTXOs).
            // Merge those signatures into Sparrow's original PSBT instead of replacing it.
            PSBT combined = psbt.copy();
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
            throw new DeviceException("Invalid signed PSBT from Banshee: " + e.getMessage(), e);
        }
    }

    private static PSBT parseDeviceSignedPsbt(String signedB64) throws PSBTParseException, DeviceException {
        String cleaned = signedB64 == null ? "" : signedB64.replaceAll("\\s+", "");
        if(cleaned.isEmpty()) {
            throw new DeviceException("Banshee returned an empty signed PSBT");
        }
        byte[] signedBytes;
        try {
            signedBytes = Base64.getDecoder().decode(cleaned);
        } catch(IllegalArgumentException e) {
            try {
                signedBytes = Base64.getMimeDecoder().decode(signedB64);
            } catch(IllegalArgumentException e2) {
                throw new DeviceException("Banshee returned invalid Base64", e);
            }
        }
        return new PSBT(signedBytes, false);
    }

    BansheeEntropyReport getEntropyReport() throws DeviceException {
        try(BansheeGate gate = openGate()) {
            return new BansheeEntropyReport(gate.getEntropyProof(), gate.getRngHealth());
        }
    }

    @Override
    String signMessage(String message, String path) throws DeviceException {
        throw new DeviceException("Banshee does not support message signing yet");
    }

    @Override
    String displaySinglesigAddress(String path, ScriptType scriptType) throws DeviceException {
        try(BansheeGate gate = openGate()) {
            ensureOracleUnlocked(gate);
            ExtendedKey pub = ExtendedKey.fromDescriptor(gate.getXpub(path));
            Address address = scriptType.getAddress(PolicyType.SINGLE_HD, pub.getKey());
            return gate.showAddress(address.toString());
        }
    }

    public BansheeInfo getInfo() throws DeviceException {
        try(BansheeGate gate = openGate()) {
            return gate.getInfo();
        }
    }

    public BansheeWalletStatus walletStatus() throws DeviceException {
        try(BansheeGate gate = openGate()) {
            return gate.walletStatus();
        }
    }

    public BansheeUnlockStatus unlockStatus() throws DeviceException {
        try(BansheeGate gate = openGate()) {
            return gate.unlockStatus();
        }
    }

    public BansheeUnlockStatus setUnlock() throws DeviceException {
        try(BansheeGate gate = openGate()) {
            return gate.setUnlock();
        }
    }

    public BansheeUnlockStatus setOracle(String url, String pubkeyHex) throws DeviceException {
        try(BansheeGate gate = openGate()) {
            return gate.setOracle(url, pubkeyHex);
        }
    }

    public BansheeUnlockStatus unlockOracle() throws DeviceException {
        try(BansheeGate gate = openGate()) {
            return gate.unlockOracle();
        }
    }

    public BansheeUnlockStatus setOracleAndUnlock(String url, String pubkeyHex) throws DeviceException {
        try(BansheeGate gate = openGate()) {
            try {
                gate.setOracle(url, pubkeyHex);
            } catch(DeviceException e) {
                String msg = e.getMessage() == null ? "" : e.getMessage();
                if(!msg.contains("unknown_cmd")) {
                    throw e;
                }
            }
            return gate.setUnlock();
        }
    }

    private static void ensureOracleUnlocked(BansheeGate gate) throws DeviceException {
        BansheeUnlockStatus status = gate.unlockStatus();
        if(status.oracle() && (status.locked() || !status.session())) {
            gate.unlockOracle();
        } else if(status.locked()) {
            throw new DeviceException("Unlock the device first");
        }
    }

    public BansheeDiceResult generateDiceWallet(java.util.function.Consumer<String> onProgress) throws DeviceException {
        try(BansheeGate gate = openGate()) {
            BansheeWalletStatus status = gate.walletStatus();
            if(status.ready()) {
                throw new DeviceException("Wallet already exists on device");
            }
            BansheeUnlockStatus unlock = gate.unlockStatus();
            if(!unlock.configured()) {
                throw new DeviceException("Set a hardware lock sequence on this device before generating a seed");
            }
            ensureOracleUnlocked(gate);
            try {
                gate.setOracle(BansheeOracle.DEVICE_URL, BansheeOracle.pubkey());
            } catch(DeviceException e) {
                String msg = e.getMessage() == null ? "" : e.getMessage();
                if(!msg.contains("unknown_cmd")) {
                    throw e;
                }
            }
            BansheeInfo info = gate.getInfo();
            progress(onProgress, "Clearing any prior roll session…");
            gate.rollCancel();
            progress(onProgress, "Press RIGHT on the device to generate. LEFT rejects.");
            gate.rollBegin(BansheeEntropyProof.WALLET_DICE_WORDS);
            List<String> diceCodes = new ArrayList<>();
            List<String> words = new ArrayList<>();
            try {
                for(int w = 1; w <= BansheeEntropyProof.WALLET_DICE_WORDS; w++) {
                    progress(onProgress, "Word " + w + "/" + BansheeEntropyProof.WALLET_DICE_WORDS + ": rolling dice on device…");
                    BansheeRollWord roll = gate.rollWord();
                    if(roll.effWord() == null || roll.effWord().isBlank()) {
                        throw new DeviceException("Device did not return an EFF word for roll " + w);
                    }
                    diceCodes.add(roll.dice());
                    words.add(roll.effWord());
                    progress(onProgress, "Word " + w + "/" + BansheeEntropyProof.WALLET_DICE_WORDS);
                    BansheeSerialProbe.sleep(250);
                }
                progress(onProgress, "Device attesting roll transcript…");
                BansheeRollAttestation attestation = gate.rollProve();
                BansheeEntropyProof.Report proof = BansheeEntropyProof.verify(info.deviceId(), diceCodes, words, attestation);
                if(!proof.allOk()) {
                    String failed = proof.steps().stream().filter(s -> !s.ok()).map(BansheeEntropyProof.Step::label)
                            .reduce((a, b) -> a + ", " + b).orElse("unknown");
                    throw new DeviceException("Entropy proof failed: " + failed);
                }
                progress(onProgress, "Write the 12 dice rolls from the device (3 screens), then press RIGHT to save. If the lock screen appears, enter the sequence — LEFT is part of it, not cancel.");
                BansheeWalletStatus saved = gate.walletCommitRoll();
                return new BansheeDiceResult(saved.fingerprint(), proof);
            } catch(DeviceException e) {
                try {
                    gate.rollCancel();
                } catch(DeviceException ignored) {
                }
                throw e;
            }
        }
    }

    public String cloneExport() throws DeviceException {
        try(BansheeGate gate = openGate()) {
            ensureOracleUnlocked(gate);
            return gate.cloneExport();
        }
    }

    public String backupWrap() throws DeviceException {
        try(BansheeGate gate = openGate()) {
            ensureOracleUnlocked(gate);
            return gate.backupWrap();
        }
    }

    public void backupWrapSet(String hex) throws DeviceException {
        try(BansheeGate gate = openGate()) {
            ensureOracleUnlocked(gate);
            gate.backupWrapSet(hex);
        }
    }

    public BansheeWalletStatus cloneImport(String payload) throws DeviceException {
        return cloneImport(payload, null);
    }

    public BansheeWalletStatus cloneImport(String payload, String oraclePub) throws DeviceException {
        try(BansheeGate gate = openGate()) {
            BansheeWalletStatus wallet = gate.walletStatus();
            if(wallet.ready()) {
                throw new DeviceException("Wallet already exists on device");
            }
            String pub = oraclePub == null || oraclePub.isBlank() ? BansheeOracle.pubkey() : oraclePub.trim();
            try {
                gate.setOracle(BansheeOracle.DEVICE_URL, pub);
            } catch(DeviceException e) {
                String msg = e.getMessage() == null ? "" : e.getMessage();
                if(!msg.contains("unknown_cmd")) {
                    throw e;
                }
            }
            return gate.cloneImport(payload);
        }
    }

    public BansheeWalletStatus walletDelete() throws DeviceException {
        try(BansheeGate gate = openGate()) {
            ensureOracleUnlocked(gate);
            return gate.walletDelete();
        }
    }

    private static void progress(java.util.function.Consumer<String> onProgress, String msg) {
        if(onProgress != null) {
            onProgress.accept(msg);
        }
    }

    public record BansheeDiceResult(String fingerprint, BansheeEntropyProof.Report proof) {
    }

    @Override
    String displayMultisigAddress(OutputDescriptor outputDescriptor) throws DeviceException {
        Address address = outputDescriptor.getAddress(outputDescriptor.getReceivingDerivation(0));
        try(BansheeGate gate = openGate()) {
            ensureOracleUnlocked(gate);
            return gate.showAddress(address.toString());
        }
    }

    @Override
    public String getPath() {
        return path;
    }

    @Override
    public HardwareType getHardwareType() {
        return HardwareType.BANSHEE;
    }

    @Override
    public WalletModel getModel() {
        return WalletModel.BANSHEE;
    }

    @Override
    public Boolean needsPinSent() {
        return false;
    }

    @Override
    public Boolean needsPassphraseSent() {
        return false;
    }

    @Override
    public String fingerprint() {
        return masterFingerprint;
    }

    @Override
    public boolean card() {
        return false;
    }

    @Override
    public String[][] warnings() {
        return new String[0][];
    }
}
