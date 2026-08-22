using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Foundation;
using Windows.Storage.Streams;

internal static class BansheeBle {
    static readonly Guid NUS = new Guid("6E400001-B5A3-F393-E0A9-E50E24DCCA9E");
    static readonly Guid RX = new Guid("6E400002-B5A3-F393-E0A9-E50E24DCCA9E");
    static readonly Guid TX = new Guid("6E400003-B5A3-F393-E0A9-E50E24DCCA9E");
    const int CHUNK = 180;

    [STAThread]
    static int Main(string[] args) {
        try {
            Console.InputEncoding = Encoding.UTF8;
            Console.OutputEncoding = Encoding.UTF8;
            if (args.Length > 0 && string.Equals(args[0], "scan", StringComparison.OrdinalIgnoreCase)) {
                ScanMode(8000);
                return 0;
            }
            Found found;
            if (args.Length >= 2 && string.Equals(args[0], "connect", StringComparison.OrdinalIgnoreCase)) {
                found = new Found();
                found.Addr = ParseAddr(args[1]);
                found.Type = args.Length >= 3 ? ParseType(args[2]) : BluetoothAddressType.Unspecified;
                found.Name = "";
            } else {
                Console.Error.WriteLine("scanning");
                found = FindFirst(10000);
            }
            Connect(found);
            return 0;
        } catch (Exception ex) {
            Console.Error.WriteLine(Friendly(ex));
            return 1;
        }
    }

    struct Found {
        public ulong Addr;
        public BluetoothAddressType Type;
        public string Name;
    }

    static void ScanMode(int timeoutMs) {
        Console.Error.WriteLine("scanning");
        List<Found> found = ScanAll(timeoutMs);
        for (int i = 0; i < found.Count; i++) {
            Found f = found[i];
            string name = f.Name == null || f.Name.Length == 0 ? "Banshee" : f.Name;
            Console.WriteLine(name + "\t" + AddrHex(f.Addr) + "\t" + f.Type.ToString());
        }
        Console.Out.Flush();
    }

    static Found FindFirst(int timeoutMs) {
        List<Found> all = ScanAll(timeoutMs);
        if (all.Count < 1) {
            throw new Exception("No Banshee Bluetooth device. Keep the board powered (USB power is enough), stay close, and turn computer Bluetooth on.");
        }
        return all[0];
    }

    static List<Found> ScanAll(int timeoutMs) {
        Dictionary<ulong, Found> map = new Dictionary<ulong, Found>();
        ScanInto(map, BluetoothLEScanningMode.Passive, timeoutMs);
        if (map.Count == 0) {
            try {
                ScanInto(map, BluetoothLEScanningMode.Active, timeoutMs);
            } catch (Exception ex) {
                if (map.Count == 0) throw new Exception(Friendly(ex));
            }
        }
        return new List<Found>(map.Values);
    }

    static void ScanInto(Dictionary<ulong, Found> map, BluetoothLEScanningMode mode, int timeoutMs) {
        BluetoothLEAdvertisementWatcher watcher = new BluetoothLEAdvertisementWatcher();
        watcher.ScanningMode = mode;
        object gate = new object();
        watcher.Received += delegate(BluetoothLEAdvertisementWatcher w, BluetoothLEAdvertisementReceivedEventArgs e) {
            if (!IsBanshee(e)) return;
            lock (gate) {
                Found f = new Found();
                f.Addr = e.BluetoothAddress;
                f.Type = e.BluetoothAddressType;
                f.Name = e.Advertisement.LocalName;
                map[f.Addr] = f;
            }
        };
        watcher.Start();
        try {
            Thread.Sleep(timeoutMs);
        } finally {
            watcher.Stop();
        }
    }

    static bool IsBanshee(BluetoothLEAdvertisementReceivedEventArgs e) {
        string name = e.Advertisement.LocalName;
        if (name != null && name.IndexOf("Banshee", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        IList<Guid> uuids = e.Advertisement.ServiceUuids;
        if (uuids == null) return false;
        for (int i = 0; i < uuids.Count; i++) {
            if (uuids[i] == NUS) return true;
        }
        return false;
    }

    static void Connect(Found found) {
        BluetoothLEDevice dev = OpenDevice(found);
        if (dev == null) throw new Exception("Could not open Banshee over Bluetooth.");
        GattDeviceService service = OpenNus(dev);
        GattCharacteristic tx = Characteristic(service, TX);
        GattCharacteristic rx = Characteristic(service, RX);
        EnableNotify(tx);
        object gate = new object();
        StringBuilder acc = new StringBuilder();
        tx.ValueChanged += delegate(GattCharacteristic c, GattValueChangedEventArgs e) {
            byte[] bytes = ReadBuffer(e.CharacteristicValue);
            lock (gate) {
                for (int i = 0; i < bytes.Length; i++) {
                    byte b = bytes[i];
                    if (b == (byte)'\r') continue;
                    if (b == (byte)'\n') {
                        Console.WriteLine(acc.ToString());
                        Console.Out.Flush();
                        acc.Length = 0;
                    } else {
                        acc.Append((char)b);
                    }
                }
            }
        };
        Console.Error.WriteLine("connected");
        string line;
        while ((line = Console.ReadLine()) != null) {
            byte[] data = Encoding.UTF8.GetBytes(line + "\n");
            for (int off = 0; off < data.Length; off += CHUNK) {
                int n = Math.Min(CHUNK, data.Length - off);
                IBuffer buf = WriteBuffer(data, off, n);
                GattCommunicationStatus st = WriteChar(rx, buf);
                if (st != GattCommunicationStatus.Success) {
                    throw new Exception("Bluetooth write failed.");
                }
                if (data.Length > 256) Thread.Sleep(8);
            }
        }
    }

    static BluetoothLEDevice OpenDevice(Found found) {
        BluetoothAddressType[] types = new BluetoothAddressType[] {
            found.Type,
            BluetoothAddressType.Public,
            BluetoothAddressType.Random,
            BluetoothAddressType.Unspecified
        };
        Exception last = null;
        for (int i = 0; i < types.Length; i++) {
            try {
                BluetoothLEDevice dev = Await(BluetoothLEDevice.FromBluetoothAddressAsync(found.Addr, types[i]), 8000);
                if (dev != null) return dev;
            } catch (Exception ex) {
                last = ex;
            }
        }
        try {
            return Await(BluetoothLEDevice.FromBluetoothAddressAsync(found.Addr), 8000);
        } catch (Exception ex) {
            last = ex;
        }
        if (last != null) throw last;
        return null;
    }

    static GattDeviceService OpenNus(BluetoothLEDevice dev) {
        GattDeviceService service = NusFrom(dev, BluetoothCacheMode.Cached);
        if (service != null) return service;
        service = NusFrom(dev, BluetoothCacheMode.Uncached);
        if (service != null) return service;
        throw new Exception("That Bluetooth device is not a Banshee.");
    }

    static GattDeviceService NusFrom(BluetoothLEDevice dev, BluetoothCacheMode cache) {
        try {
            GattDeviceServicesResult svcs = Await(dev.GetGattServicesForUuidAsync(NUS, cache), 8000);
            if (svcs.Status == GattCommunicationStatus.Success && svcs.Services.Count > 0) {
                return svcs.Services[0];
            }
        } catch {
        }
        try {
            GattDeviceServicesResult all = Await(dev.GetGattServicesAsync(cache), 8000);
            if (all.Status != GattCommunicationStatus.Success) return null;
            for (int i = 0; i < all.Services.Count; i++) {
                if (all.Services[i].Uuid == NUS) return all.Services[i];
            }
        } catch {
        }
        return null;
    }

    static GattCharacteristic Characteristic(GattDeviceService service, Guid uuid) {
        GattCharacteristicsResult cached = Await(service.GetCharacteristicsForUuidAsync(uuid, BluetoothCacheMode.Cached), 8000);
        if (cached.Characteristics.Count > 0) return cached.Characteristics[0];
        GattCharacteristicsResult fresh = Await(service.GetCharacteristicsForUuidAsync(uuid, BluetoothCacheMode.Uncached), 8000);
        if (fresh.Characteristics.Count > 0) return fresh.Characteristics[0];
        throw new Exception("Banshee UART characteristics missing.");
    }

    static void EnableNotify(GattCharacteristic tx) {
        try {
            GattCommunicationStatus notify = Await(tx.WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue.Notify), 8000);
            if (notify == GattCommunicationStatus.Success) return;
        } catch {
        }
        throw new Exception("Could not subscribe to Banshee Bluetooth notifies.");
    }

    static GattCommunicationStatus WriteChar(GattCharacteristic rx, IBuffer buf) {
        try {
            return Await(rx.WriteValueAsync(buf, GattWriteOption.WriteWithoutResponse), 8000);
        } catch {
        }
        return Await(rx.WriteValueAsync(buf), 8000);
    }

    static ulong ParseAddr(string hex) {
        string h = hex == null ? "" : hex.Trim();
        if (h.StartsWith("0x") || h.StartsWith("0X")) h = h.Substring(2);
        h = h.Replace(":", "").Replace("-", "");
        return Convert.ToUInt64(h, 16);
    }

    static BluetoothAddressType ParseType(string raw) {
        if (string.Equals(raw, "Public", StringComparison.OrdinalIgnoreCase)) return BluetoothAddressType.Public;
        if (string.Equals(raw, "Random", StringComparison.OrdinalIgnoreCase)) return BluetoothAddressType.Random;
        return BluetoothAddressType.Unspecified;
    }

    static string AddrHex(ulong addr) {
        return addr.ToString("X12");
    }

    static string Friendly(Exception ex) {
        string msg = ex.Message == null ? "" : ex.Message;
        if (msg.IndexOf("80070016", StringComparison.OrdinalIgnoreCase) >= 0
            || msg.IndexOf("does not recognize the command", StringComparison.OrdinalIgnoreCase) >= 0) {
            return "Windows Bluetooth rejected the board. Toggle Bluetooth off and on, keep the board powered (USB power is enough), then Scan Bluetooth again.";
        }
        return msg;
    }

    static T Await<T>(IAsyncOperation<T> op, int timeoutMs) {
        long deadline = DateTime.UtcNow.Ticks + (long)timeoutMs * TimeSpan.TicksPerMillisecond;
        while (op.Status == AsyncStatus.Started && DateTime.UtcNow.Ticks < deadline) {
            Thread.Sleep(15);
        }
        if (op.Status == AsyncStatus.Started) {
            try { op.Cancel(); } catch { }
            throw new Exception("Bluetooth timed out.");
        }
        if (op.Status != AsyncStatus.Completed) {
            throw new Exception(op.ErrorCode != null ? op.ErrorCode.Message : op.Status.ToString());
        }
        return op.GetResults();
    }

    static byte[] ReadBuffer(IBuffer buffer) {
        DataReader reader = DataReader.FromBuffer(buffer);
        byte[] bytes = new byte[buffer.Length];
        reader.ReadBytes(bytes);
        return bytes;
    }

    static IBuffer WriteBuffer(byte[] data, int off, int n) {
        DataWriter writer = new DataWriter();
        byte[] part = new byte[n];
        Array.Copy(data, off, part, 0, n);
        writer.WriteBytes(part);
        return writer.DetachBuffer();
    }
}
