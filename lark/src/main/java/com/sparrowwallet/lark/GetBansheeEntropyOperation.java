package com.sparrowwallet.lark;

public class GetBansheeEntropyOperation extends AbstractClientOperation {
    private BansheeEntropyReport report;

    public GetBansheeEntropyOperation(String devicePath) {
        super(HardwareType.BANSHEE.getName(), devicePath);
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        if(!(hardwareClient instanceof BansheeClient banshee)) {
            throw new DeviceException("Not a Banshee");
        }
        report = banshee.getEntropyReport();
    }

    public BansheeEntropyReport getReport() {
        return report;
    }

    @Override
    public boolean success() {
        return report != null;
    }
}
