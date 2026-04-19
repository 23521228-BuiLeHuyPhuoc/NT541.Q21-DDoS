from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.lib import hub
from collections import Counter
import math
import time
from datetime import datetime
import requests

# ============================================================
# THU IMPORT INFLUXDB CLIENT
# Neu khong co, se dung REST API truc tiep (requests)
# ============================================================
HAS_INFLUX_LIB = False
try:
    from influxdb import InfluxDBClient
    HAS_INFLUX_LIB = True
except ImportError:
    pass


class SimpleRouterEntropy(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleRouterEntropy, self).__init__(*args, **kwargs)
        
        # --- CAU HINH MANG ---
        self.mac = '00:00:00:00:00:FE'
        self.arp_table = {}
        self.routes = {'10.0.1.': 1, '10.0.2.': 2, '10.0.3.': 3, '10.0.4.': 4}
        self.gateways = ['10.0.1.1', '10.0.2.1', '10.0.3.1', '10.0.4.1']
        self.dps = {}
        
        # --- BIEN THONG KE ENTROPY ---
        self.WINDOW_SIZE = 1000
        self.src_ip_window = []
        self.blocked_ips = set()
        self.packet_rate = 0
        
        self.ENTROPY_HIGH = 8.0
        self.ENTROPY_LOW = 1.5
        self.attack_status = 0
        
        self.WHITELIST_SRC = {
            '10.0.2.10', '10.0.2.11',
            '10.0.3.10', '10.0.3.11',
            '10.0.4.10', '10.0.4.11',
            '10.0.1.20'
        }
        
        # --- CAU HINH INFLUXDB ---
        self.INFLUX_HOST = 'localhost'
        self.INFLUX_PORT = 8086
        self.INFLUX_DB = 'sdn_monitor'
        
        # --- KET NOI INFLUXDB ---
        self.influx_client = None
        self.use_rest_api = False  # Fallback: dung REST API neu thu vien khong hoat dong
        
        self._setup_influxdb()
        
        # --- FLOW STATS ---
        self.flow_stats = {}
        self.total_pps = 0

        hub.spawn(self._monitor_entropy)
        hub.spawn(self._monitor_flows)

    def _setup_influxdb(self):
        """Ket noi va kiem tra InfluxDB. Thu nhieu cach."""
        
        self.logger.info("=" * 60)
        self.logger.info("[INFLUXDB] BAT DAU KET NOI...")
        self.logger.info("[INFLUXDB] Host: %s, Port: %d, DB: %s",
                        self.INFLUX_HOST, self.INFLUX_PORT, self.INFLUX_DB)
        
        # ---- CACH 1: Dung thu vien influxdb (pip install influxdb) ----
        if HAS_INFLUX_LIB:
            self.logger.info("[INFLUXDB] Tim thay thu vien 'influxdb'. Thu ket noi...")
            try:
                client = InfluxDBClient(
                    host=self.INFLUX_HOST,
                    port=self.INFLUX_PORT,
                    database=self.INFLUX_DB
                )
                # Test ket noi bang cach ping
                version = client.ping()
                self.logger.info("[INFLUXDB] Ping thanh cong! Version: %s", version)
                
                # Tao database
                client.create_database(self.INFLUX_DB)
                self.logger.info("[INFLUXDB] Database '%s' da san sang!", self.INFLUX_DB)
                
                # Test ghi du lieu
                test_point = [{
                    "measurement": "connection_test",
                    "fields": {"status": 1}
                }]
                client.write_points(test_point)
                self.logger.info("[INFLUXDB] Test ghi du lieu THANH CONG!")
                
                self.influx_client = client
                self.logger.info("[INFLUXDB] ====> KET NOI THANH CONG (thu vien influxdb) <====")
                self.logger.info("=" * 60)
                return
                
            except Exception as e:
                self.logger.error("[INFLUXDB] Thu vien influxdb THAT BAI: %s", e)
                self.logger.info("[INFLUXDB] Thu cach 2: REST API...")
        else:
            self.logger.warning("[INFLUXDB] Khong co thu vien 'influxdb'. Thu REST API...")
        
        # ---- CACH 2: Dung REST API truc tiep (requests) ----
        try:
            # Ping InfluxDB
            url = "http://{}:{}/ping".format(self.INFLUX_HOST, self.INFLUX_PORT)
            resp = requests.get(url, timeout=3)
            self.logger.info("[INFLUXDB] REST Ping: status=%d", resp.status_code)
            
            if resp.status_code == 204:
                # Tao database
                create_url = "http://{}:{}/query".format(self.INFLUX_HOST, self.INFLUX_PORT)
                resp2 = requests.post(create_url,
                    params={"q": "CREATE DATABASE {}".format(self.INFLUX_DB)},
                    timeout=3)
                self.logger.info("[INFLUXDB] Create DB status: %d", resp2.status_code)
                
                # Test ghi
                write_url = "http://{}:{}/write?db={}".format(
                    self.INFLUX_HOST, self.INFLUX_PORT, self.INFLUX_DB)
                test_data = "connection_test status=1i"
                resp3 = requests.post(write_url, data=test_data, timeout=3)
                self.logger.info("[INFLUXDB] Test write status: %d", resp3.status_code)
                
                if resp3.status_code == 204:
                    self.use_rest_api = True
                    self.logger.info("[INFLUXDB] ====> KET NOI THANH CONG (REST API) <====")
                    self.logger.info("=" * 60)
                    return
                else:
                    self.logger.error("[INFLUXDB] Test write THAT BAI: %s", resp3.text)
            else:
                self.logger.error("[INFLUXDB] Ping THAT BAI (status != 204)")
                
        except requests.exceptions.ConnectionError:
            self.logger.error("[INFLUXDB] KHONG THE KET NOI den %s:%d",
                            self.INFLUX_HOST, self.INFLUX_PORT)
            self.logger.error("[INFLUXDB] Kiem tra: InfluxDB da chay chua? (sudo systemctl status influxdb)")
        except Exception as e:
            self.logger.error("[INFLUXDB] REST API loi: %s", e)
        
        self.logger.error("=" * 60)
        self.logger.error("[INFLUXDB] KHONG THE KET NOI INFLUXDB!")
        self.logger.error("[INFLUXDB] Kiem tra:")
        self.logger.error("[INFLUXDB]   1. InfluxDB da cai chua?  (sudo apt install influxdb)")
        self.logger.error("[INFLUXDB]   2. InfluxDB da chay chua? (sudo systemctl start influxdb)")
        self.logger.error("[INFLUXDB]   3. Port 8086 mo chua?     (curl http://localhost:8086/ping)")
        self.logger.error("[INFLUXDB]   4. Thu vien Python?       (pip install influxdb requests)")
        self.logger.error("=" * 60)

    def _write_influx(self, json_body):
        """Ghi du lieu vao InfluxDB. Ho tro ca thu vien va REST API."""
        
        # Cach 1: Thu vien influxdb
        if self.influx_client:
            try:
                self.influx_client.write_points(json_body)
                return True
            except Exception as e:
                self.logger.error("[INFLUXDB] Loi ghi (library): %s", e)
                return False
        
        # Cach 2: REST API
        if self.use_rest_api:
            try:
                write_url = "http://{}:{}/write?db={}".format(
                    self.INFLUX_HOST, self.INFLUX_PORT, self.INFLUX_DB)
                
                # Chuyen JSON body sang InfluxDB line protocol
                lines = []
                for point in json_body:
                    measurement = point["measurement"]
                    
                    # Tags
                    tag_str = ""
                    if "tags" in point:
                        tags = ",".join("{}={}".format(k, v) for k, v in point["tags"].items())
                        tag_str = "," + tags
                    
                    # Fields
                    field_parts = []
                    for k, v in point["fields"].items():
                        if isinstance(v, int):
                            field_parts.append("{}={}i".format(k, v))
                        elif isinstance(v, float):
                            field_parts.append("{}={}".format(k, v))
                        else:
                            field_parts.append('{}="{}"'.format(k, v))
                    fields = ",".join(field_parts)
                    
                    lines.append("{}{}  {}".format(measurement, tag_str, fields))
                
                data = "\n".join(lines)
                resp = requests.post(write_url, data=data, timeout=3)
                
                if resp.status_code == 204:
                    return True
                else:
                    self.logger.error("[INFLUXDB] REST write loi: %d %s", resp.status_code, resp.text)
                    return False
                    
            except Exception as e:
                self.logger.error("[INFLUXDB] Loi ghi (REST): %s", e)
                return False
        
        return False

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
            hub.sleep(3)
            
            current_packetin_rate = self.packet_rate
            self.packet_rate = 0
            entropy = 0.0
            current_pps = self.total_pps
            window_size = len(self.src_ip_window)
            
            if window_size < 100:
                self.logger.info("[ENTROPY] Chua du mau: %d/100 (packet_in=%d, pps=%d)",
                                window_size, current_packetin_rate, current_pps)
            
            if window_size >= 100: 
                ip_counts = Counter(self.src_ip_window)
                total_packets = len(self.src_ip_window)
                
                for count in ip_counts.values():
                    probability = count / total_packets
                    entropy -= probability * math.log2(probability)
                
                self.logger.info("[ENTROPY] Entropy = %.2f | Window = %d | Unique IPs = %d",
                                entropy, total_packets, len(ip_counts))
                
                if entropy < self.ENTROPY_LOW:
                    self.attack_status = 1
                    self.logger.warning("\n[!] PHAT HIEN DoS FIXED IP (LOW ENTROPY = %.2f)", entropy)
                    
                    for ip, count in ip_counts.items():
                        if (count / total_packets) > 0.20 and ip not in self.blocked_ips:
                            if ip in self.WHITELIST_SRC:
                                self.logger.info(" => Bo qua IP %s (Whitelist)!", ip)
                                continue
                            self.logger.warning(" => Thu pham: %s (%d goi). DROP 60s!", ip, count)
                            self._block_ip(ip)
                    self.src_ip_window.clear()
                    
                elif entropy > self.ENTROPY_HIGH:
                    self.attack_status = 2
                    self.logger.warning("\n[!] PHAT HIEN DoS SPOOFED IP (HIGH ENTROPY = %.2f)", entropy)
                    self.logger.warning(" => DROP ALL IPv4 + BAO VE Whitelist!")
                    
                    for dp in self.dps.values():
                        parser = dp.ofproto_parser
                        
                        match_all = parser.OFPMatch(eth_type=0x0800)
                        inst_drop = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, [])]
                        mod_drop = parser.OFPFlowMod(
                            datapath=dp, priority=40, match=match_all,
                            instructions=inst_drop, hard_timeout=10
                        )
                        dp.send_msg(mod_drop)
                        
                        for wl_ip in self.WHITELIST_SRC:
                            match_wl = parser.OFPMatch(eth_type=0x0800, ipv4_src=wl_ip)
                            mod_allow = parser.OFPFlowMod(
                                datapath=dp, priority=60, match=match_wl,
                                instructions=[],
                                hard_timeout=10
                            )
                            dp.send_msg(mod_allow)
                        self.logger.info(" => Da cai flow ALLOW cho Whitelist priority=60")
                    
                    self.src_ip_window.clear()
                
                else:
                    self.attack_status = 0

            # --- GUI DU LIEU LEN GRAFANA ---
            self._send_to_grafana(current_packetin_rate, current_pps, entropy)

    def _send_to_grafana(self, packetin_rate, total_pps, entropy):
        """Gui metrics len InfluxDB"""
        
        json_body = [
            {
                "measurement": "network_traffic",
                "fields": {
                    "packet_rate": int(packetin_rate),
                    "total_pps": int(total_pps),
                    "entropy": round(float(entropy), 4),
                    "attack_status": int(self.attack_status),
                    "blocked_ip_count": int(len(self.blocked_ips)),
                    "window_fill": int(len(self.src_ip_window))
                }
            }
        ]
        
        ok = self._write_influx(json_body)
        if ok:
            self.logger.info("[GRAFANA] OK: pkt_in=%d, pps=%d, entropy=%.2f, attack=%d",
                            packetin_rate, total_pps, entropy, self.attack_status)
        else:
            self.logger.warning("[GRAFANA] THAT BAI gui du lieu!")

    def _block_ip(self, bad_ip):
        self.blocked_ips.add(bad_ip)
        
        # Gui event block
        block_body = [{
            "measurement": "blocked_events",
            "tags": {"blocked_ip": bad_ip},
            "fields": {"event": 1}
        }]
        self._write_influx(block_body)
        
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
    # QUET LUU LUONG (FLOW STATS)
    # ==========================================
    def _monitor_flows(self):
        while True:
            for dp in self.dps.values():
                req = dp.ofproto_parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
            hub.sleep(3)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        now = time.time()
        sum_pps = 0
        
        for stat in ev.msg.body:
            if stat.priority == 0:
                continue
            
            match_src = stat.match.get('ipv4_src')
            if not match_src:
                continue
            if match_src in self.gateways or match_src in self.WHITELIST_SRC:
                continue

            key = (ev.msg.datapath.id, match_src, stat.match.get('ipv4_dst'))
            prev = self.flow_stats.get(key)
            
            if prev:
                prev_pkt, prev_time = prev
                delta = now - prev_time
                if delta > 0:
                    pps = (stat.packet_count - prev_pkt) / delta
                    if pps > 0:
                        sum_pps += pps
                    
                    if pps > 500 and match_src not in self.blocked_ips:
                        self.logger.warning("[!] HIGH PPS = %d tu IP: %s => DROP 60s!", int(pps), match_src)
                        self._block_ip(match_src)
            
            self.flow_stats[key] = (stat.packet_count, now)
        
        self.total_pps = int(sum_pps)

    # ==========================================
    # 2. XU LY GOI TIN (PACKET IN)
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
            self.packet_rate += 1

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
            
            # CHI cai flow cho WHITELIST IP.
            # Non-whitelist: KHONG cai flow => moi goi luon di qua controller
            # => entropy window LUON duoc cap nhat du lieu.
            if p_ip.src in self.WHITELIST_SRC:
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=p_ip.src, ipv4_dst=p_ip.dst)
                self.add_flow(dp, 10, match, actions, idle_timeout=30)
            
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=msg.data
            )
            dp.send_msg(out)

    # ==========================================
    # 3. ADD FLOW (override - ho tro idle_timeout)
    # ==========================================
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, **kwargs):
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, idle_timeout=idle_timeout
        )
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
