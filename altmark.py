#!/usr/bin/env python

import ctypes as ct
import datetime
import time
import pprint

import pyroute2
from bcc import BPF
from concurrent.futures import ThreadPoolExecutor
import grpc
import packet_stats_pb2
import packet_stats_pb2_grpc


# We use two colors, 0 and 1, alternately.
class Color(int):
    def __init__(self, color=0):
        self = color
    def next(self):
        return Color(1 if self == 0 else 0)
    def prev(self):
        return Color(1 if self == 0 else 0)


# pktstats - bpf array
#   [0]: the packet counter for color 0
#   [1]: the packet counter for color 0
#   [2]: the color
class PktStatsWrapper:
    def __init__(self, pktstats):
        self.pktstats = pktstats

    def get_count0(self):
        return self.pktstats[ct.c_int(0)].value

    def get_count1(self):
        return self.pktstats[ct.c_int(1)].value

    def get_color(self):
        return Color(self.pktstats[ct.c_int(2)].value)

    def set_color(self, color):
        self.pktstats[ct.c_int(2)] = ct.c_int(color)


prog = r"""
// SPDX-License-Identifier: GPL-2.0+
#define BPF_LICENSE GPL

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/pkt_cls.h>
#include <bcc/proto.h>
#include <asm/types.h>

BPF_ARRAY(pktstats, long, 3);

enum {
    ARRAY_IDX_COUNTER0 = 0,
    ARRAY_IDX_COUNTER1,
    ARRAY_IDX_COLOR,
};

// from samples/bpf/tcbpf1_kern.c
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TOS_OFF (ETH_HLEN + offsetof(struct iphdr, tos))

static inline void set_ip_tos(struct __sk_buff *skb, __u8 new_tos)
{
        __u8 old_tos = load_byte(skb, TOS_OFF);

        bpf_l3_csum_replace(skb, IP_CSUM_OFF, htons(old_tos), htons(new_tos), 2);
        bpf_skb_store_bytes(skb, TOS_OFF, &new_tos, sizeof(new_tos), 0);
}

static inline __u8 color2tos(int color)
{
        return (__u8)((1 << 3) | (color << 2));
}

int bpf_prog_source(struct __sk_buff *skb)
{
        int index = ARRAY_IDX_COLOR;
        int color = -1;
        long *value;
        uint8_t tos;

        if (skb->protocol != htons(ETH_P_IP))
                return TC_ACT_OK;

        value = pktstats.lookup(&index);
        if (!value)
                return TC_ACT_OK;
        color = index = (int)*value;

        /* If TOS is used, don't modify it */
        tos = load_byte(skb, TOS_OFF);
        if (tos != 0)
                return TC_ACT_OK;

        set_ip_tos(skb, color2tos(color));
#if 0
        struct iphdr iphdr;
        ret = bpf_skb_load_bytes(skb, ETH_HLEN, &iphdr, sizeof(iphdr));
        if (ret < 0) {
                //printk("bpf_skb_load_bytes failed: %d\n", ret);
                return TC_ACT_OK;
        }
        bpf_trace_printk("iphdr=%lx\n", *(int*)&iphdr);
#endif

        value = pktstats.lookup(&index);
        if (value)
                lock_xadd(value, 1);
        return TC_ACT_OK;
}

static int extract_color(struct __sk_buff *skb)
{
        __u8 old_tos = load_byte(skb, TOS_OFF);

        //bpf_trace_printk("old_tos=%u\n", old_tos);
        if ((old_tos & (1 << 3)) == 0)
                return -1;
        set_ip_tos(skb, 0);

        return (int)((old_tos & (1 << 2)) >> 2);
}

int bpf_prog_sink(struct __sk_buff *skb)
{
        int color = -1;
        int index = -1;
        long *value;

        if (skb->protocol != htons(ETH_P_IP))
                return TC_ACT_OK;

        index = extract_color(skb);
        //bpf_trace_printk("index=%d\n", index);
        if (index == -1)
                return TC_ACT_OK;

        color = index;
        value = pktstats.lookup(&index);
        if (value)
                lock_xadd(value, 1);

        index = ARRAY_IDX_COLOR;
        value = pktstats.lookup(&index);
        if (value)
                *value = color;
        return TC_ACT_OK;
}
"""


class PacketStatsCollector(packet_stats_pb2_grpc.PacketStatsCollectorServicer):
    def __init__(self):
        self.counters = {}
        self.counters[0] = {}
        self.counters[1] = {}
        self.diffs = {}
        self.diffs[0] = {}
        self.diffs[1] = {}

    def get(self, request, context):
        # pprint.pprint(request.stats)
        self.store_data(request.stats)
        self.calc(request.stats.block_number, request.stats.interval)
        message = pprint.pformat(request)
        return packet_stats_pb2.PacketStatsPushResult(error=False, message=message)

    def store_data(self, stats):
        counter = self.counters[stats.role]
        counter[stats.block_number] = stats.counter0 if stats.color == 0 else stats.counter1

        if (stats.block_number - 2) in counter:
            prev = counter[stats.block_number - 2]
            diff = counter[stats.block_number] - prev
            diffs = self.diffs[stats.role]
            diffs[stats.block_number] = (diff, stats.color)

    def calc(self, block_number, interval):
        if block_number not in self.diffs[0]:
            return
        if block_number not in self.diffs[1]:
            return

        (diff0, color0) = self.diffs[0][block_number]
        (diff1, color1) = self.diffs[1][block_number]

        if color0 != color1:
            print("error: colors are different!")
            return

        timestamp = block_number * interval
        dt = datetime.datetime.fromtimestamp(timestamp)
        print("[{}] loss={}".format(dt, abs(diff0 - diff1)))


def main_collector(args):
    server = grpc.server(ThreadPoolExecutor(max_workers=2))
    packet_stats_pb2_grpc.add_PacketStatsCollectorServicer_to_server(PacketStatsCollector(), server)
    server.add_insecure_port("[::]:" + args.port)
    server.start()
    # XXX server.wait_for_termination()
    try:
        while True:
            time.sleep(3600)
    finally:
        server.stop(0)


def send_stats(is_source, n, color, counter0, counter1, interval, debug=False):
    stats = packet_stats_pb2.PacketStats()
    role = 'SOURCE' if is_source else 'SINK'
    stats.role = packet_stats_pb2.PacketStats.Role.Value(role)
    stats.block_number = n
    stats.color = color
    stats.counter0 = counter0
    stats.counter1 = counter1
    stats.interval = interval

    req = packet_stats_pb2.PacketStatsPush(stats=stats)
    with grpc.insecure_channel('{}:{}'.format(args.address, args.port)) as channel:
        stub = packet_stats_pb2_grpc.PacketStatsCollectorStub(channel)
        result = stub.get(req)
    if debug:
        pprint.pprint(result)


def calc_block_number(now, interval):
    return int(now / interval)


def main_source(args):
    bpf = BPF(text=prog, debug=args.bpf_debug)
    bpf_prog = bpf.load_func("bpf_prog_source", BPF.SCHED_CLS)
    pktstats = PktStatsWrapper(bpf["pktstats"])

    ipr = pyroute2.IPRoute()
    idx = ipr.get_links(ifname=args.interface)[0]['index']
    ipr.tc("add", "clsact", idx)
    # set up a filter for egress packets
    ipr.tc("add-filter", "bpf", idx, ":1", fd=bpf_prog.fd, name=bpf_prog.name,
           parent="ffff:fff3", classid=1, direct_action=True)

    color = Color()

    try:
        pktstats.set_color(color)
        time.sleep(args.interval)
        color = color.next()
        # no need to send stats

        while True:
            pktstats.set_color(color)
            now = time.time()
            count0 = pktstats.get_count0()
            count1 = pktstats.get_count1()
            print("color {} count0 {} count1 {}".format(color, count0, count1))
            # print(bpf.trace_fields()[5])

            n = calc_block_number(now, args.interval)
            prev = color.prev()
            # sending a count of a previous color
            send_stats(True, n, prev, count0, count1, args.interval, args.debug)

            time.sleep(args.interval)
            color = color.next()
    finally:
        ipr.tc("del", "clsact", idx)


def main_sink(args):
    bpf = BPF(text=prog, debug=args.bpf_debug)
    bpf_prog = bpf.load_func("bpf_prog_sink", BPF.SCHED_CLS)
    pktstats = PktStatsWrapper(bpf["pktstats"])

    ipr = pyroute2.IPRoute()
    idx = ipr.get_links(ifname=args.interface)[0]['index']
    ipr.tc("add", "clsact", idx)
    # set up a filter for ingress packets
    ipr.tc("add-filter", "bpf", idx, ":1", fd=bpf_prog.fd, name=bpf_prog.name,
           parent="ffff:fff2", classid=1, direct_action=True)

    color = Color(-1)

    try:
        # sync with source
        while True:
            old = color
            color = pktstats.get_color()
            if old != -1 and color != old:
                break
            time.sleep(1)

        while True:
            # detect a color switch
            while True:
                old = color
                color = pktstats.get_color()
                if color != old:
                    # need a timestamp at this point
                    now = time.time()
                    break
                time.sleep(1)

            # wait until OoO packets passed
            time.sleep(args.interval / 2)

            count0 = pktstats.get_count0()
            count1 = pktstats.get_count1()
            color = pktstats.get_color()
            print("color {} count0 {} count1 {}".format(color, count0, count1))
            # print(bpf.trace_fields()[5])

            n = calc_block_number(now, args.interval)
            prev = color.prev()
            # sending a count of a previous color
            send_stats(False, n, prev, count0, count1, args.interval, args.debug)
    finally:
        ipr.tc("del", "clsact", idx)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', action="store_true")
    parser.add_argument('--bpf-debug', type=int, default=0)
    parser.add_argument('-i', '--interval', type=int, default=10)

    subparsers = parser.add_subparsers()

    collector = subparsers.add_parser('collector', help='packet stats collector')
    collector.add_argument('port', help='Listening port')
    collector.set_defaults(func=main_collector)

    source = subparsers.add_parser('source', help='altmark on source')
    source.add_argument('interface', help='interface to sniff')
    source.add_argument('address', help='Collector\'s address')
    source.add_argument('port', help='Collector\'s port')
    source.set_defaults(func=main_source)

    sink = subparsers.add_parser('sink', help='altmark on sink')
    sink.add_argument('interface', help='interface to sniff')
    sink.add_argument('address', help='Collector\'s address')
    sink.add_argument('port', help='Collector\'s port')
    sink.set_defaults(func=main_sink)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()
