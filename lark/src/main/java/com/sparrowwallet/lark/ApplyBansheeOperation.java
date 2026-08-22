package com.sparrowwallet.lark;

public class ApplyBansheeOperation extends AbstractClientOperation {
    private final ClientFn fn;
    private Object result;
    private boolean done;

    public ApplyBansheeOperation(String devicePath, ClientFn fn) {
        super(HardwareType.BANSHEE.getName(), devicePath);
        this.fn = fn;
    }

    @Override
    public void apply(HardwareClient hardwareClient) throws DeviceException {
        if(!(hardwareClient instanceof BansheeClient banshee)) {
            throw new DeviceException("Not a Banshee");
        }
        result = fn.apply(banshee);
        done = true;
    }

    @SuppressWarnings("unchecked")
    public <T> T getResult() {
        return (T)result;
    }

    @Override
    public boolean success() {
        return done;
    }

    @FunctionalInterface
    public interface ClientFn {
        Object apply(BansheeClient client) throws DeviceException;
    }
}
