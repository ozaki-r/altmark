# altmark

This is an experimental implementation of RFC 8321, leveraging eBPF.

## RFC 8321 (Alternate-Marking Method for Passive and Hybrid Performance Monitoring)

RFC 8321 proposes the Alternate-Marking Method, a means of packet measurements such as
packet losses and packet delays between nodes.

**altmark** implements the method to measure only packet losses of IPv4 packets.

## Implementation

**altmark** consists of three roles of programs: a source-side daemon, a sink-side daemon, and a collector.

The current implementation uses two bits of the DSCP field of the IPv4 header to color packets.
If the field is already used, i.e., it's not zero, it does nothing for the packets.

The source-side daemon marks a color into packets on a waching interface by using eBPF.
It switches the color every 10 seconds (default).
It counts the number of packets for each color and sends the counts to the collector via gRPC.

The sink-side daemon sniffs packets on a watching interface, and counts the number of packets,
and resets the DSCP field of the packets if needed by using eBPF.
It also reports the counts to the collector.

The collector gathers the counts of packets of both ends, calculates packes losses, and reports the results.

## How to use

First, run a collector on a node that has an IP address `10.0.0.1`:

```
python3 altmark.py collector 12345
```

Then, run a source-side deamon on a node where you want to sniff outgoing packets:

```
sudo python3 altmark.py source eth0 10.0.0.1 12345
```

Finally, run a source-side deamon on a node where you want to sniff incoming packets:

```
sudo python3 altmark.py sink eth0 10.0.0.1 12345
```

After some time, you can see outputs of the collector how much packets are lost (or not) like this:

```
[2020-09-20 08:08:20] loss=0
[2020-09-20 08:08:30] loss=0
[2020-09-20 08:08:40] loss=0
[2020-09-20 08:08:50] loss=0
[2020-09-20 08:09:00] loss=0
[2020-09-20 08:09:10] loss=0
[2020-09-20 08:09:20] loss=1
[2020-09-20 08:09:30] loss=0
[2020-09-20 08:09:40] loss=0
[2020-09-20 08:09:50] loss=0
[2020-09-20 08:10:00] loss=0
[2020-09-20 08:10:10] loss=4
[2020-09-20 08:10:20] loss=0
[2020-09-20 08:10:30] loss=0
```

# License

GPLv2
