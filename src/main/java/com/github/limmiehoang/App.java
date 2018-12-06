package com.github.limmiehoang;

import java.io.IOException;

import com.sun.jna.Platform;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.NifSelector;

public class App {

    static PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;
        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;
    }

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        PcapNetworkInterface device = getNetworkDevice();
        System.out.println("You chose: " + device);

        if (device == null) {
            System.out.println("No device chosen.");
            System.exit(1);
        }

        // Open the device and get a handle
        int snapshotLength = 65536; // in bytes   
        int readTimeout = 50; // in milliseconds                   
        final PcapHandle handle;
        handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
        PcapDumper dumper = handle.dumpOpen("out.pcap");

        // Set a filter to only listen for tcp packets on port 80 (HTTP)
        // String filter = "tcp";
        // handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
        // Create a listener that defines what to do with the received packets
        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                
                System.out.println("======= Got a packet =======");

                System.out.println(handle.getTimestamp());

                if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ipv4p = packet.get(IpV4Packet.class);
                    System.out.println("-----IpV4Packet Header-----");
                    System.out.println(ipv4p.getHeader());
                    System.out.println("-----IpV4Packet Payload----");
                    System.out.println(ipv4p.getPayload());
                }
                if (packet.contains(IpV6Packet.class)) {
                    IpV6Packet ipv6p = packet.get(IpV6Packet.class);
                    System.out.println("-----IpV6Packet Header-----");
                    System.out.println(ipv6p.getHeader());
                    System.out.println("-----IpV6Packet Payload----");
                    System.out.println(ipv6p.getPayload());
                }

                else {
                    System.out.println("-----Packet Header-----");
                    System.out.println(packet.getHeader());
                    System.out.println("-----Packet Payload----");
                    System.out.println(packet.getPayload());
                }


                // Dump packets to file
                try {
                    dumper.dump(packet, handle.getTimestamp());
                } catch (NotOpenException e) {
                    e.printStackTrace();
                }
            }
        };

        // Tell the handle to loop using the listener we created
        try {
            int maxPackets = 5;
            handle.loop(maxPackets, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Print out handle statistics
        PcapStat stats = handle.getStats();
        System.out.println("Packets received: " + stats.getNumPacketsReceived());
        System.out.println("Packets dropped: " + stats.getNumPacketsDropped());
        System.out.println("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());
        // Supported by WinPcap only
        if (Platform.isWindows()) {
            System.out.println("Packets captured: " +stats.getNumPacketsCaptured());
        }

        // Cleanup when complete
        dumper.close();
        handle.close();
    }
}
