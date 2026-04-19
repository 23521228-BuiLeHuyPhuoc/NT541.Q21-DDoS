from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
from ryu.lib import hub
import time


class Layer3Router(simple_switch_13.SimpleSwitch13):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Layer3Router, self).__init__(*args, **kwargs)

        # ========================
        # ROUTER CONFIG
        # ========================
        self.arp_table = {}

        self.core_switch_dpid = 2
        self.router_mac = '00:00:00:00:00:FE'

        self.routing_table = {
            '10.0.1.': 1,
            '10.0.2.': 2,
            '10.0.3.': 3,
            '10.0.4.': 4
        }

        self.gateway_ips = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']

        # ========================
        # TRAFFIC EXTRACTOR
        # ========================
        self.datapaths = {}
        self.flow_stats = {}
        self.port_stats = {}

        self.monitor_thread = hub.spawn(self._monitor)

    # ========================
    # TRACK SWITCH
    # ========================
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    # ========================
    # MONITOR THREAD
    # ========================
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self.request_stats(dp)
            hub.sleep(5)

    def request_stats(self, datapath):
        parser = datapath.ofproto_parser

        # Flow stats
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # Port stats
        req = parser.OFPPortStatsRequest(
            datapath, 0, datapath.ofproto.OFPP_ANY)
        datapath.send_msg(req)

    # ========================
    # FLOW STATS HANDLER
    # ========================
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):

        dpid = ev.msg.datapath.id
        now = time.time()

        for stat in ev.msg.body:

            if stat.priority == 0:
                continue

            key = (dpid, str(stat.match))
            prev = self.flow_stats.get(key)

            if prev:
                prev_pkt, prev_byte, prev_time = prev
                delta = now - prev_time
                if delta > 0:
                    pps = (stat.packet_count - prev_pkt) / delta
                    bps = (stat.byte_count - prev_byte) / delta

                    self.logger.info(f"[FLOW] DPID={dpid} {stat.match}")
                    self.logger.info(f"   PPS={pps:.2f}, BPS={bps:.2f}")

                    # 👉 hook cho detection
                    if pps > 1000:
                        self.logger.warning(f"⚠️ HIGH TRAFFIC DETECTED: {pps:.2f} PPS")

            self.flow_stats[key] = (
                stat.packet_count,
                stat.byte_count,
                now
            )

    # ========================
    # PORT STATS HANDLER
    # ========================
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):

        dpid = ev.msg.datapath.id
        now = time.time()

        for stat in ev.msg.body:

            port = stat.port_no
            key = (dpid, port)
            prev = self.port_stats.get(key)

            if prev:
                prev_rx, prev_tx, prev_time = prev
                delta = now - prev_time

                if delta > 0:
                    rx_pps = (stat.rx_packets - prev_rx) / delta
                    tx_pps = (stat.tx_packets - prev_tx) / delta

                    self.logger.info(f"[PORT] SW={dpid} PORT={port}")
                    self.logger.info(f"   RX_PPS={rx_pps:.2f}, TX_PPS={tx_pps:.2f}")

            self.port_stats[key] = (
                stat.rx_packets,
                stat.tx_packets,
                now
            )

    # ========================
    # TABLE MISS
    # ========================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                match=match,
                                instructions=inst)

        datapath.send_msg(mod)

    # ========================
    # PACKET IN
    # ========================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # EDGE → L2
        if dpid != self.core_switch_dpid:
            super(Layer3Router, self)._packet_in_handler(ev)
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.handle_arp(datapath, in_port, eth, arp_pkt)
            return

        if ip_pkt:
            self.handle_ipv4(msg, datapath, in_port, eth, ip_pkt)

    # ========================
    # ARP
    # ========================
    def handle_arp(self, datapath, in_port, eth, arp_pkt):

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac

        if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip in self.gateway_ips:

            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_ARP,
                dst=eth.src,
                src=self.router_mac
            ))
            pkt.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=self.router_mac,
                src_ip=arp_pkt.dst_ip,
                dst_mac=arp_pkt.src_mac,
                dst_ip=arp_pkt.src_ip
            ))
            pkt.serialize()

            actions = [parser.OFPActionOutput(in_port)]

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=pkt.data
            )
            datapath.send_msg(out)

    # ========================
    # ARP REQUEST
    # ========================
    def send_arp_request(self, datapath, out_port, target_ip):

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst='ff:ff:ff:ff:ff:ff',
            src=self.router_mac
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=self.router_mac,
            src_ip='0.0.0.0',
            dst_mac='00:00:00:00:00:00',
            dst_ip=target_ip
        ))
        pkt.serialize()

        actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)

    # ========================
    # IPV4 ROUTING
    # ========================
    def handle_ipv4(self, msg, datapath, in_port, eth, ip_pkt):

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        dst_ip = ip_pkt.dst
        out_port = None

        for subnet, port in self.routing_table.items():
            if dst_ip.startswith(subnet):
                out_port = port
                break

        if not out_port:
            return

        if dst_ip not in self.arp_table:
            self.logger.info(f"ARP miss {dst_ip}")
            self.send_arp_request(datapath, out_port, dst_ip)
            return

        dst_mac = self.arp_table[dst_ip]

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_dst=dst_ip
        )

        actions = [
            parser.OFPActionSetField(eth_src=self.router_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionOutput(out_port)
        ]

        self.add_flow(datapath, 10, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
