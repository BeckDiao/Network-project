from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp


class SimpleSwitch10(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(SimpleSwitch10, self).__init__(*args, **kwargs)
        # arp table: for searching
        self.arp_table={}
        self.arp_table["10.0.0.1"] = "00:00:00:00:00:01"
        self.arp_table["10.0.0.2"] = "00:00:00:00:00:02"

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        in_port = msg.in_port
        arp_out_port = in_port

        tcp_out_port = 0
        if in_port == 1:
            tcp_out_port = 2
        elif in_port == 2:
            tcp_out_port = 1

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth.ethertype
        dpid = datapath.id

        # process ARP
        if ethertype == ether_types.ETH_TYPE_ARP:
            self.handle_arp(datapath, arp_out_port, pkt)
            return

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # process IP
        if ethertype == ether_types.ETH_TYPE_IP and ipv4_pkt.proto == in_proto.IPPROTO_TCP:
            self.handle_ip(datapath, tcp_out_port, pkt)
            if dpid == 1:
                self.add_layer4_rules(datapath, in_proto.IPPROTO_TCP,
                                      '10.0.0.1', '10.0.0.2', 10001, 5, 2)
                self.add_layer4_rules(datapath, in_proto.IPPROTO_TCP,
                                      '10.0.0.2', '10.0.0.1', 0, 5, 1)
                return
            elif dpid == 2:
                self.add_layer4_rules(datapath, in_proto.IPPROTO_TCP,
                                      '10.0.0.1', '10.0.0.2', 10001, 5, 1)
                self.add_layer4_rules(datapath, in_proto.IPPROTO_TCP,
                                      '10.0.0.2', '10.0.0.1', 0, 5, 2)
                return


    # Member methods you can call to install TCP/UDP/ICMP fwding rules
    def add_layer4_rules(self, datapath, ip_proto, ipv4_src=None, ipv4_dst=None,
                         tcp_dst=0, priority=1, fwd_port=None):
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(fwd_port)]
        match = parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_proto=ip_proto,
                                tp_dst=tcp_dst, nw_src=ipv4_src, nw_dst=ipv4_dst)
        self.add_flow(datapath, priority, match, actions)


    # Member methods you can call to install general rules
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD,
                                priority=priority, flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)


    def handle_arp(self, datapath, arp_out_port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # parse out the ethernet and arp packet
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        # obtain the MAC of dst IP  
        arp_resolv_mac = self.arp_table[arp_pkt.dst_ip]
        # generate the ARP reply msg
        eth_head = ethernet.ethernet(src=arp_resolv_mac, dst=eth_pkt.src,
                                     ethertype=ether_types.ETH_TYPE_ARP)
        arp_head = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                         src_mac=arp_resolv_mac, src_ip=arp_pkt.dst_ip,
                         dst_mac=eth_pkt.src, dst_ip=arp_pkt.src_ip)
        arp_reply = packet.Packet()
        arp_reply.add_protocol(eth_head)
        arp_reply.add_protocol(arp_head)
        arp_reply.serialize()
        
        # send the Packet Out msg to back to the host who is initilaizing the ARP
        actions = [parser.OFPActionOutput(arp_out_port)];
        out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER, 
                                  ofproto.OFPP_CONTROLLER, actions,
                                  arp_reply.data)
        datapath.send_msg(out)


    def handle_ip(self, datapath, tcp_out_port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # send the Packet Out msg og ip packets to another port.
        actions = [parser.OFPActionOutput(tcp_out_port)];
        out = parser.OFPPacketOut(datapath, ofproto.OFP_NO_BUFFER,
                                  ofproto.OFPP_CONTROLLER, actions,
                                  pkt.data)
        datapath.send_msg(out)


