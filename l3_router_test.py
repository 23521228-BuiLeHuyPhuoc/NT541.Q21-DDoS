from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub
from collections import Counter
import math
import time

try:
    from influxdb import InfluxDBClient
    HAS_INFLUX = True
except ImportError:
    HAS_INFLUX = False


class SimpleRouterEntropy(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleRouterEntropy, self).__init__(*args, **kwargs)

        # --- CAU HINH MANG ---
        self.mac = '00:00:00:00:00:FE'
        self.arp_table = {}
        self.routes = {'10.0.1.': 1, '10.0.2.': 2, '10.0.3.': 3, '10.0.4.': 4}
        self.gateways = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']
        self.dps = {}

      # --- CAU HINH ENTROPY VA THEO DOI TRAFFIC ---
        self.WINDOW_SIZE = 1000            # SO LUONG GOI LUU TRONG WINDOW
        self.src_ip_window = []            # DANH SACH IP NGUON GAN DAY
        self.src_mac_window = []           # DANH SACH MAC TUONG UNG
        self.blocked_ips = set()           # TAP IP DA BI CHAN
        self.blocked_macs = set()          # TAP MAC DA BI CHAN
        self.packet_rate = 0               # DEM SO GOI TRONG MOI CHU KY
        self.ENTROPY_HIGH = 8.0            # NGUONG CAO (NGHI NGO SPOOF)
        self.ENTROPY_LOW = 1.5             # NGUONG THAP (NGHI NGO 1 IP TAN CONG)
        self.attack_status = 0             # 0: BINH THUONG, 1: TAN CONG IP, 2: SPOOF
        
        # DANH SACH IP HOP LE (KHONG BI CHAN)
        self.WHITELIST_SRC = {
            '10.0.2.10', '10.0.2.11',
            '10.0.3.10', '10.0.3.11',
            '10.0.4.10', '10.0.4.11',
            '10.0.1.20'
        }

        # --- INFLUXDB ---
        self.influx_client = None
        if HAS_INFLUX:
            try:
                self.influx_client = InfluxDBClient(host='localhost', port=8086, database='sdn_monitor')
                self.influx_client.create_database('sdn_monitor')
                self.influx_client.write_points([{"measurement": "test", "fields": {"ok": 1}}])
                self.logger.info("[INFLUXDB] Da ket noi thanh cong den InfluxDB (sdn_monitor)")
            except Exception as e:
                self.logger.error("[INFLUXDB] Khong the ket noi den InfluxDB: %s", e)
                self.influx_client = None
        else:
            self.logger.warning("[INFLUXDB] Thu vien influxdb chua duoc cai dat. Chay: pip install influxdb")

        # --- FLOW STATS ---
        self.flow_stats = {}
        self.total_pps = 0

        hub.spawn(self._monitor_entropy)
        hub.spawn(self._monitor_flows)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.dps[dp.id] = dp
        elif dp.id in self.dps:
            del self.dps[dp.id]

# KIEM TRA ENTROPY DE PHAT HIEN TRAFFIC BAT THUONG 
    def _monitor_entropy(self):
        while True:
            hub.sleep(3)

            current_rate = self.packet_rate
            self.packet_rate = 0
            entropy = 0.0
            current_pps = self.total_pps
            window_size = len(self.src_ip_window)

            if window_size >= 100:
                ip_counts = Counter(self.src_ip_window)
                total = len(self.src_ip_window)

                for count in ip_counts.values():
                    p = count / total
                    entropy -= p * math.log2(p)

                self.logger.info("[ENTROPY] Gia tri entropy = %.2f | Tong goi = %d | So IP duy nhat = %d", entropy, total, len(ip_counts))

                if entropy < self.ENTROPY_LOW:
                    self.attack_status = 1
                    self.logger.warning("[CANH BAO] Phat hien tan cong DoS bang IP co dinh! Entropy = %.2f (nguong < %.2f)", entropy, self.ENTROPY_LOW)
                    for ip, count in ip_counts.items():
                        if (count / total) > 0.20 and ip not in self.blocked_ips:
                            if ip in self.WHITELIST_SRC:
                                continue
                            self.logger.warning("[BLOCK] Chan IP %s — da gui %d goi (chiem %.1f%% tong traffic)", ip, count, (count/total)*100)
                            self._block_ip(ip)
                    self.src_ip_window.clear()
                    self.src_mac_window.clear()

                elif entropy > self.ENTROPY_HIGH:
                    self.attack_status = 2
                    self.logger.warning("[CANH BAO] Phat hien tan cong DoS bang IP gia mao! Entropy = %.2f (nguong > %.2f)", entropy, self.ENTROPY_HIGH)
                    # Tim MAC gui nhieu nhat — chinh la MAC thuc cua ke tan cong
                    mac_counts = Counter(self.src_mac_window)
                    for mac, count in mac_counts.most_common():
                        if mac not in self.blocked_macs:
                            self.logger.warning("[BLOCK] Chan MAC %s — da gui %d goi spoof (chiem %.1f%% tong traffic)", mac, count, (count/total)*100)
                            self._block_mac(mac)
                    self.src_ip_window.clear()
                    self.src_mac_window.clear()
                else:
                    self.attack_status = 0
            else:
                pass

           # --- GUI DU LIEU LEN INFLUXDB ---
            if self.influx_client:
                try:
                    self.influx_client.write_points([{
                        "measurement": "network_traffic",
                        "fields": {
                            "packet_rate": int(current_rate),
                            "total_pps": int(current_pps),
                            "entropy": round(float(entropy), 4),
                            "attack_status": int(self.attack_status),
                            "blocked_ip_count": int(len(self.blocked_ips)),
                            "blocked_mac_count": int(len(self.blocked_macs)),
                            "window_fill": int(window_size)
                        }
                    }])
                except Exception as e:
                    self.logger.error("[INFLUXDB] Khong the ghi du lieu vao InfluxDB: %s", e)

    def _block_ip(self, bad_ip):
        self.blocked_ips.add(bad_ip)
        for dp in self.dps.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=bad_ip)
            inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=100, match=match,
                instructions=inst, hard_timeout=60))

        def unblock():
            hub.sleep(61)
            self.blocked_ips.discard(bad_ip)
            self.logger.info("[UNBLOCK] Da go chan IP %s sau 60 giay", bad_ip)
        hub.spawn(unblock)

    def _block_mac(self, bad_mac):
        self.blocked_macs.add(bad_mac)
        for dp in self.dps.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_src=bad_mac)
            inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, priority=100, match=match,
                instructions=inst, hard_timeout=60))

        def unblock():
            hub.sleep(61)
            self.blocked_macs.discard(bad_mac)
            self.logger.info("[UNBLOCK] Da go chan MAC %s sau 60 giay", bad_mac)
        hub.spawn(unblock)

   #  THEO DOI FLOW DE TINH TOC DO GOI
    def _monitor_flows(self):
        while True:
            for dp in self.dps.values():
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            hub.sleep(3)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        now = time.time()
        sum_pps = 0
        for stat in ev.msg.body:
            if stat.priority == 0:
                continue
            src = stat.match.get('ipv4_src')
            if not src or src in self.gateways or src in self.WHITELIST_SRC:
                continue
            key = (ev.msg.datapath.id, src, stat.match.get('ipv4_dst'))
            prev = self.flow_stats.get(key)
            if prev:
                delta = now - prev[1]
                if delta > 0:
                    pps = (stat.packet_count - prev[0]) / delta
                    if pps > 0:
                        sum_pps += pps
                    if pps > 500 and src not in self.blocked_ips:
                        self.logger.warning("[BLOCK] Chan IP %s — toc do qua cao: %d goi/giay (nguong: 500)", src, int(pps))
                        self._block_ip(src)
            self.flow_stats[key] = (stat.packet_count, now)
        self.total_pps = int(sum_pps)

     # XU LY PACKET IN TU SWITCH
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        p_eth = pkt.get_protocol(ethernet.ethernet)
        if p_eth.ethertype == 0x88CC:
            return

        if dp.id != 2:
            return super(SimpleRouterEntropy, self)._packet_in_handler(ev)

        p_arp = pkt.get_protocol(arp.arp)
        p_ip = pkt.get_protocol(ipv4.ipv4)

        if p_arp:
            self.arp_table[p_arp.src_ip] = p_arp.src_mac
            if p_arp.opcode == arp.ARP_REQUEST and p_arp.dst_ip in self.gateways:
                self._send_arp(dp, in_port, p_eth.src, arp.ARP_REPLY,
                               self.mac, p_arp.dst_ip, p_arp.src_mac, p_arp.src_ip)
            return

        if p_ip:
            self.packet_rate += 1

            if p_ip.src not in self.gateways and p_ip.src not in self.WHITELIST_SRC:
                self.src_ip_window.append(p_ip.src)
                self.src_mac_window.append(p_eth.src)
                if len(self.src_ip_window) > self.WINDOW_SIZE:
                    self.src_ip_window.pop(0)
                    self.src_mac_window.pop(0)

            out_port = None
            for net, port in self.routes.items():
                if p_ip.dst.startswith(net):
                    out_port = port
                    break
            if not out_port:
                return

            if p_ip.dst not in self.arp_table:
                self._send_arp(dp, out_port, 'ff:ff:ff:ff:ff:ff', arp.ARP_REQUEST,
                               self.mac, '0.0.0.0', '00:00:00:00:00:00', p_ip.dst)
                return

            parser = dp.ofproto_parser
            actions = [
                parser.OFPActionSetField(eth_src=self.mac),
                parser.OFPActionSetField(eth_dst=self.arp_table[p_ip.dst]),
                parser.OFPActionOutput(out_port)
            ]

            # Chi cai flow cho whitelist IP, non-whitelist luon di qua controller
            if p_ip.src in self.WHITELIST_SRC:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst)
                self.add_flow(dp, 10, match, actions, idle_timeout=30)

            dp.send_msg(parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=msg.data))

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, **kwargs):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout))

    def _send_arp(self, dp, port, eth_dst, opcode, s_mac, s_ip, d_mac, d_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=eth_dst, src=self.mac))
        pkt.add_protocol(arp.arp(opcode=opcode, src_mac=s_mac, src_ip=s_ip, dst_mac=d_mac, dst_ip=d_ip))
        pkt.serialize()
        dp.send_msg(dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=[dp.ofproto_parser.OFPActionOutput(port)], data=pkt.data))
