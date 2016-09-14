from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import in_proto
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.ofproto import inet


def int_to_hex(i):
    if i > 255 or i < 0:
        return "00"
    else:
        return hex(i)[2:4]


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.arp_table = {}
        self.switches = {}
        for i in xrange(1, 17):
            ip = "10.0.0." + str(i)
            mac = "00:00:00:00:00:" + int_to_hex(i)
            self.arp_table[ip] = mac
        self.core_to_agg = [[1, 2, 2, 1], [1, 1, 2, 2], [2, 1, 1, 2], [2, 2, 1, 1]]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        self.switches[datapath.id] = datapath

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        in_port = msg.in_port

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth.ethertype

        # process ARP
        if ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, in_port, pkt)
            return

        # process IP
        if ethertype == ether_types.ETH_TYPE_IP:
            self.handle_ip(datapath, pkt)
            return

    def add_layer4_rules(self, datapath, ipv4_dst=None,
                         priority=1, fwd_port=None):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(fwd_port)]
        match = parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,
                                nw_dst=ipv4_dst)
        self.add_flow(datapath, priority, match, actions)

    # Member methods you can call to install general rules
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD,
                                idle_timeout=0, hard_timeout=0, priority=priority,
                                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def handle_arp(self, datapath, in_port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # parse out the ethernet and arp packet
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        # obtain the MAC of dst IP
        arp_resolv_mac = self.arp_table[arp_pkt.dst_ip]
        ether_hd = ethernet.ethernet(dst=eth_pkt.src,
                                     src=arp_resolv_mac,
                                     ethertype=0x0806)
        arp_hd = arp.arp(hwtype=1, proto=0x0800,
                         hlen=6, plen=4, opcode=2,
                         src_mac=arp_resolv_mac,
                         src_ip=arp_pkt.dst_ip,
                         dst_mac=arp_pkt.src_mac,
                         dst_ip=arp_pkt.src_ip)
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ether_hd)
        arp_reply.add_protocol(arp_hd)
        arp_reply.serialize()

        # send the Packet Out mst to back to the host who is initilaizing the ARP
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                  ofproto.OFPP_CONTROLLER, actions,
                                  arp_reply.data)
        datapath.send_msg(out)

    def handle_ip(self, datapath, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # implement algorithm LPR
        src1 = int(ipv4_pkt.src.split('.')[3]) - 1
        if src1 < 0:
            return
        dst1 = int(ipv4_pkt.dst.split('.')[3]) - 1
        if dst1 < 0:
            return
        edge1 = src1 / 2 + 1
        edge1_dp = self.switches.get(edge1)
        self.add_layer4_rules(edge1_dp, ipv4_pkt.dst, 10, 3)
        edge2 = dst1 / 2 + 1
        edge2_dp = self.switches.get(edge2)
        self.add_layer4_rules(edge2_dp, ipv4_pkt.dst, 10, dst1 % 2 + 1)

        if edge1 % 2 == 1:
            agg1 = edge1 + 8
        else:
            agg1 = edge1 + 7
        agg1_dp = self.switches.get(agg1)
	if agg1 == 12 or agg1 == 15:
	    agg_port = 4
	else:
	    agg_port = 3
        self.add_layer4_rules(agg1_dp, ipv4_pkt.dst, 10, agg_port)

        pod_id = (agg1 - 9) / 2
        if agg1 % 2 == 0:
            core1 = 19 + pod_id
        else:
            core1 = 17 + pod_id

        if core1 > 20:
            core1 = core1 - 4

        core2 = core1 + 1
        if core2 > 20:
            core2 = core2 - 4
        core = min(core1, core2)
        core_dp = self.switches.get(core)
        core_port = dst1/4 + 1
        self.add_layer4_rules(core_dp, ipv4_pkt.dst, 10, core_port)

        agg2 = self.core_to_agg[core - 17][dst1 / 4] + (dst1 / 4) * 2 + 8
        agg2_dp = self.switches.get(agg2)
        self.add_layer4_rules(agg2_dp, ipv4_pkt.dst, 10, (dst1 / 2) % 2 + 1)

        # IP packets are simply forwarded to the other port of the switch
        actions = [parser.OFPActionOutput(3)]
        out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                  ofproto.OFPP_CONTROLLER, actions,
                                  pkt.data)
        datapath.send_msg(out)
