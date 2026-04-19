from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub
from collections import Counter
import math
import time
from datetime import datetime

# Import thư viện InfluxDB
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
        # Port tren s2: port1=s1 (10.0.1.x), port2=s3 (10.0.2.x), port3=s4 (10.0.3.x), port4=s5 (10.0.4.x)
        self.routes = {'10.0.1.': 1, '10.0.2.': 2, '10.0.3.': 3, '10.0.4.': 4}
        self.gateways = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']
        self.dps = {}
        
        # --- BIEN THONG KE ENTROPY ---
        self.WINDOW_SIZE = 1000       # Kich thuoc cua so truot (luu 1000 IP gan nhat)
        self.src_ip_window = []       # Mang luu tru IP
        self.blocked_ips = set()      # Danh sach cac IP dang bi khoa
        self.packet_rate = 0          # Bien dem so goi tin moi 3 giay (cho Grafana)
        
        # Nguong Entropy
        self.ENTROPY_HIGH = 8.0       # > 8.0: Gia mao IP (Spoofed IP)
        self.ENTROPY_LOW = 1.5        # < 1.5: DoS IP co dinh
        
        # Whitelist: cac IP hop le khong tham gia vao tinh Entropy va khong bi block
        # Cac may thuoc Internal, DMZ, PC zone va ext1
        self.WHITELIST_SRC = {
            '10.0.2.10', '10.0.2.11', # DMZ (web1, dns1)
            '10.0.3.10', '10.0.3.11', # DB/App
            '10.0.4.10', '10.0.4.11', # PC1, PC2
            '10.0.1.20'               # ext1
        }
        
        # --- KET NOI INFLUXDB ---
        if HAS_INFLUX:
            try:
                self.influx_client = InfluxDBClient(host='localhost', port=8086)
                # Tu dong tao database neu chua co
                self.influx_client.create_database('sdn_monitor')
                self.influx_client.switch_database('sdn_monitor')
                self.logger.info("[GRAFANA] Da ket noi InfluxDB va tao DB thanh cong!")
            except Exception as e:
                self.logger.error("[GRAFANA] Loi ket noi InfluxDB: %s", e)
                self.influx_client = None
        else:
            self.influx_client = None
            self.logger.warning("[GRAFANA] Chua cai thu vien influxdb (pip install influxdb)")

        hub.spawn(self._monitor_entropy)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER: 
            self.dps[dp.id] = dp
        elif dp.id in self.dps: 
            del self.dps[dp.id]

    # ==========================================
    # 1. THUAT TOAN TINH ENTROPY & MITIGATION
    # ==========================================
    def _monitor_entropy(self):
        while True:
            hub.sleep(3) # Kiem tra moi 3 giay
            
            # Lay rate va reset de dem cho chu ky tiep theo
            current_rate = self.packet_rate
            self.packet_rate = 0
            entropy = 0.0
            
            # Chi tinh toan va chong tan cong neu co du 100 mau
            if len(self.src_ip_window) >= 100: 
                ip_counts = Counter(self.src_ip_window)
                total_packets = len(self.src_ip_window)
                
                for count in ip_counts.values():
                    probability = count / total_packets
                    entropy -= probability * math.log2(probability)
                
                # KICH BAN 1: TAN CONG TU IP CO DINH (DoS - Fixed IP)
                if entropy < self.ENTROPY_LOW:
                    self.logger.warning("\n[!] PHAT HIEN DoS FIXED IP (LOW ENTROPY = %.2f)", entropy)
                    
                    for ip, count in ip_counts.items():
                        if (count / total_packets) > 0.20 and ip not in self.blocked_ips:
                            if ip in self.WHITELIST_SRC:
                                self.logger.info(" => Bo qua IP %s vi nam trong Whitelist (Server/Client hop le)!", ip)
                                continue
                            self.logger.warning(" => Thu pham: %s (Giao %d goi tin). DROP TRONG 60 GIAY!", ip, count)
                            self._block_ip(ip)
                    self.src_ip_window.clear()
                    
                # KICH BAN 2: TAN CONG GIA MAO IP (DoS - SPOOFED IP / RANDOM SOURCE)
                elif entropy > self.ENTROPY_HIGH:
                    self.logger.warning("\n[!] PHAT HIEN DoS SPOOFED IP (HIGH ENTROPY = %.2f)", entropy)
                    self.logger.warning(" => DROP ALL IPv4 (priority=40, 10s) + BAO VE ext1 (priority=60)!")
                    
                    for dp in self.dps.values():
                        parser = dp.ofproto_parser
                        
                        # Buoc 1: DROP tat ca IPv4 voi priority thap (40)
                        match_all = parser.OFPMatch(eth_type=0x0800)
                        inst_drop = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
                        mod_drop = parser.OFPFlowMod(
                            datapath=dp, priority=40, match=match_all,
                            instructions=inst_drop, hard_timeout=10
                        )
                        dp.send_msg(mod_drop)
                        
                        # Buoc 2: ALLOW cac host trong Whitelist voi priority cao hon (60)
                        # Flow nay override DROP ALL, dam bao cac host hop le van di qua duoc
                        for wl_ip in self.WHITELIST_SRC:
                            match_wl = parser.OFPMatch(eth_type=0x0800, ipv4_src=wl_ip)
                            mod_allow = parser.OFPFlowMod(
                                datapath=dp, priority=60, match=match_wl,
                                instructions=[],  # GOTO_TABLE mac dinh (forward binh thuong)
                                hard_timeout=10
                            )
                            dp.send_msg(mod_allow)
                        self.logger.info(" => Da cai flow ALLOW cho toan bo Whitelist priority=60")
                    
                    self.src_ip_window.clear()

            # --- GUI DU LIEU LEN GRAFANA (INFLUXDB) ---
            if self.influx_client:
                try:
                    json_body = [{
                        "measurement": "network_traffic",
                        "time": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                        "fields": {
                            "packet_rate": current_rate,
                            "entropy": float(entropy)
                        }
                    }]
                    self.influx_client.write_points(json_body)
                except Exception as e:
                    self.logger.error("[GRAFANA] Loi gui data InfluxDB: %s", e)

    def _block_ip(self, bad_ip):
        self.blocked_ips.add(bad_ip)
        for dp in self.dps.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=bad_ip)
            inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
            mod = parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst, hard_timeout=60)
            dp.send_msg(mod)
            
        def unblock():
            hub.sleep(61)
            if bad_ip in self.blocked_ips:
                self.blocked_ips.remove(bad_ip)
                self.logger.info("[INFO] Da mo block cho IP: %s", bad_ip)
        hub.spawn(unblock)

    # ==========================================
    # 2. XU LY GOI TIN (PACKET IN) & THU THAP DATA
    # ==========================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        p_eth = pkt.get_protocol(ethernet.ethernet)
        if p_eth.ethertype == 0x88CC: return 

        if dp.id != 2:
            return super(SimpleRouterEntropy, self)._packet_in_handler(ev)

        p_arp = pkt.get_protocol(arp.arp)
        p_ip = pkt.get_protocol(ipv4.ipv4)

        if p_arp:
            self.arp_table[p_arp.src_ip] = p_arp.src_mac
            if p_arp.opcode == arp.ARP_REQUEST and p_arp.dst_ip in self.gateways:
                self._send_arp(dp, in_port, p_eth.src, arp.ARP_REPLY, self.mac, p_arp.dst_ip, p_arp.src_mac, p_arp.src_ip)
            return

        if p_ip:
            # --- DEM GOI TIN CHO GRAFANA ---
            self.packet_rate += 1

            # Chi them vao entropy window neu KHONG phai gateway hoac IP hop le (whitelist)
            if p_ip.src not in self.gateways and p_ip.src not in self.WHITELIST_SRC:
                self.src_ip_window.append(p_ip.src)
                if len(self.src_ip_window) > self.WINDOW_SIZE:
                    self.src_ip_window.pop(0)

            out_port = None
            for net, port in self.routes.items():
                if p_ip.dst.startswith(net):
                    out_port = port
                    break
            
            if not out_port: 
                return

            if p_ip.dst not in self.arp_table:
                self._send_arp(dp, out_port, 'ff:ff:ff:ff:ff:ff', arp.ARP_REQUEST, self.mac, '0.0.0.0', '00:00:00:00:00:00', p_ip.dst)
                return

            parser = dp.ofproto_parser
            actions = [
                parser.OFPActionSetField(eth_src=self.mac),
                parser.OFPActionSetField(eth_dst=self.arp_table[p_ip.dst]),
                parser.OFPActionOutput(out_port)
            ]
            
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst)
            self.add_flow(dp, 10, match, actions, idle_timeout=5)
            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def _send_arp(self, dp, port, eth_dst, opcode, s_mac, s_ip, d_mac, d_ip):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=eth_dst, src=self.mac))
        pkt.add_protocol(arp.arp(opcode=opcode, src_mac=s_mac, src_ip=s_ip, dst_mac=d_mac, dst_ip=d_ip))
        pkt.serialize()
        
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER,
            actions=[dp.ofproto_parser.OFPActionOutput(port)], data=pkt.data)
        dp.send_msg(out)
