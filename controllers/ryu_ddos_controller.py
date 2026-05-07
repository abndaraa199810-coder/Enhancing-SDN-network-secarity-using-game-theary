import os
import time
import csv
from datetime import datetime
from collections import deque
from typing import Dict, Tuple, Optional

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, ether_types

from game_engine import DynamicGameEngine, Observation


class RyuDDoSController(app_manager.RyuApp):
    """
    Ryu SDN controller integrated with a dynamic game-theoretic defense engine.

    Main features:
        1. Round-based monitoring.
        2. Snort alert integration.
        3. Game-theoretic decisions:
           ALLOW / RL_1 / RL_2 / RL_3 / BLOCK
        4. Rate limiting using OpenFlow meters.
        5. Blocking using high-priority OpenFlow drop rules.
        6. Basic IP spoofing detection using trusted IP per switch port.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Fixed meter IDs for rate-limit strategies
    METER_IDS = {
        "RL_1": 1,
        "RL_2": 2,
        "RL_3": 3,
    }

    RATE_LIMITS_KBPS = {
        "RL_1": 4000,
        "RL_2": 1024,
        "RL_3": 512,
    }

    def __init__(self, *args, **kwargs):
        super(RyuDDoSController, self).__init__(*args, **kwargs)

        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self.game_engine = DynamicGameEngine()

        # Per-flow monitoring state.
        # flow_key = (src_ip, dst_ip)
        self.flow_stats: Dict[Tuple[str, str], Dict] = {}
        self.last_rtt: Dict[Tuple[str, str], float] = {}
        self.last_packet_loss: Dict[Tuple[str, str], float] = {}

        # Round-based game evaluation
        self.game_round_interval = 3
        self.flow_stale_timeout = 20

        # Snort alert log path
        self.snort_alert_log = os.path.expanduser(
            "~/SDN-GameTheory-Security/logs/snort_alerts.log"
        )
        self.snort_alert_window_sec = 60

        # BLOCK configuration
        self.block_idle_timeout = 30

        # Safety thresholds for critical demo cases.
        # The game engine is still the main decision maker.
        # These values only force BLOCK when the state is clearly critical.
        self.critical_icmp_pps = 1300.0
        self.critical_spoofed_icmp_pps = 300.0

        self.trusted_ip_by_port = {
            1: {
                1: "10.0.0.1",
                2: "10.0.0.2",
                3: "10.0.0.3",
            },
            2: {
                1: "10.0.0.4",
                2: "10.0.0.5",
                3: "10.0.0.6",
            }
        }

        # All legitimate host IPs in the Mininet topology.
        # Any 10.0.0.x source outside this list is treated as spoofed.
        self.known_host_ips = {
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3",
            "10.0.0.4",
            "10.0.0.5",
            "10.0.0.6",
        }

        # Logs
        self.project_dir = os.path.expanduser("~/SDN-GameTheory-Security")
        self.logs_dir = os.path.join(self.project_dir, "logs")
        os.makedirs(self.logs_dir, exist_ok=True)

        self.game_decisions_log = os.path.join(self.logs_dir, "game_decisions.csv")
        self.init_game_decisions_log()

        # Background loop
        self.monitor_thread = hub.spawn(self.game_round_loop)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def init_game_decisions_log(self):
        if os.path.exists(self.game_decisions_log):
            return

        with open(self.game_decisions_log, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "src_ip",
                "dst_ip",
                "protocol",
                "in_port",
                "packet_rate_pps",
                "snort_alert",
                "is_spoofed",
                "engine_strategy",
                "final_strategy",
                "rate_kbps",
                "reputation",
                "normal_belief",
                "probe_belief",
                "flood_low_belief",
                "flood_high_belief",
                "ip_spoofing_belief",
                "spoofed_flood_belief",
                "u_allow",
                "u_rl1",
                "u_rl2",
                "u_rl3",
                "u_block",
                "round_count",
                "reason"
            ])

    def log_game_decision(
        self,
        src_ip,
        dst_ip,
        protocol,
        in_port,
        packet_rate_pps,
        snort_alert,
        is_spoofed,
        engine_strategy,
        final_strategy,
        rate_kbps,
        decision,
        reason,
    ):
        beliefs = decision.get("beliefs", {})
        utilities = decision.get("utilities", {})

        with open(self.game_decisions_log, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                src_ip,
                dst_ip,
                protocol,
                in_port,
                round(packet_rate_pps, 2),
                int(bool(snort_alert)),
                int(bool(is_spoofed)),
                engine_strategy,
                final_strategy,
                rate_kbps,
                round(decision.get("reputation", 0.0), 4),
                round(beliefs.get("NORMAL", 0.0), 4),
                round(beliefs.get("PROBE", 0.0), 4),
                round(beliefs.get("FLOOD_LOW", 0.0), 4),
                round(beliefs.get("FLOOD_HIGH", 0.0), 4),
                round(beliefs.get("IP_SPOOFING", 0.0), 4),
                round(beliefs.get("SPOOFED_FLOOD", 0.0), 4),
                round(utilities.get("ALLOW", 0.0), 4),
                round(utilities.get("RL_1", 0.0), 4),
                round(utilities.get("RL_2", 0.0), 4),
                round(utilities.get("RL_3", 0.0), 4),
                round(utilities.get("BLOCK", 0.0), 4),
                decision.get("round_count", 0),
                reason,
            ])

    # ------------------------------------------------------------------
    # Base OpenFlow helpers
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss rule: send unmatched packets to controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

        # Install meters for rate-limit actions
        self.add_meter(datapath, self.METER_IDS["RL_1"], self.RATE_LIMITS_KBPS["RL_1"])
        self.add_meter(datapath, self.METER_IDS["RL_2"], self.RATE_LIMITS_KBPS["RL_2"])
        self.add_meter(datapath, self.METER_IDS["RL_3"], self.RATE_LIMITS_KBPS["RL_3"])

        self.logger.info("Switch %s connected to controller", datapath.id)
        self.logger.info("Meters installed: RL_1=4000kbps, RL_2=1024kbps, RL_3=512kbps")

    def add_meter(self, datapath, meter_id: int, rate_kbps: int):
        """
        Install a drop-band meter.
        If the meter already exists, OVS may print an error, but the controller
        will continue running. This is acceptable during repeated tests.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        band = parser.OFPMeterBandDrop(
            rate=rate_kbps,
            burst_size=max(rate_kbps // 10, 1)
        )

        req = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=[band],
        )

        datapath.send_msg(req)

    def add_flow(
        self,
        datapath,
        priority: int,
        match,
        actions,
        meter_id: Optional[int] = None,
        idle_timeout: int = 0,
        hard_timeout: int = 0,
    ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = []

        if meter_id is not None:
            instructions.append(parser.OFPInstructionMeter(meter_id))

        instructions.append(
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    def delete_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match,
        )
        datapath.send_msg(mod)

    # ------------------------------------------------------------------
    # Protocol / spoofing helpers
    # ------------------------------------------------------------------

    def get_protocol_name(self, proto_num: int) -> str:
        if proto_num == 1:
            return "ICMP"
        if proto_num == 6:
            return "TCP"
        if proto_num == 17:
            return "UDP"
        return "OTHER"

    def protocol_name_to_num(self, protocol_name: str) -> int:
        protocol_name = str(protocol_name).upper()

        if protocol_name == "ICMP":
            return 1
        if protocol_name == "TCP":
            return 6
        if protocol_name == "UDP":
            return 17
        return 0

    def is_spoofed_source(self, dpid: int, in_port: int, src_ip: str) -> bool:
        """
        Detect IP spoofing using two checks:

        1. Host-port check:
           If a packet enters from a known host port, the source IP must match
           the expected IP address of that host.

        2. Unknown-source check:
           If the packet enters from an inter-switch port, the source IP must
           still belong to one of the legitimate Mininet hosts.
        """
        expected_ip = self.trusted_ip_by_port.get(dpid, {}).get(in_port)

        # Case 1: packet enters from a known host port
        if expected_ip is not None:
            return src_ip != expected_ip

        # Case 2: packet enters from an inter-switch port.
        # If the source is inside our lab subnet but not a real host, it is spoofed.
        if src_ip.startswith("10.0.0.") and src_ip not in self.known_host_ips:
            return True

        return False

    # ------------------------------------------------------------------
    # Rate-limit and BLOCK helpers
    # ------------------------------------------------------------------

    def build_defense_match(
        self,
        datapath,
        src_ip: str,
        dst_ip: str,
        in_port: int,
        protocol_num: int,
        is_spoofed: bool,
    ):
        parser = datapath.ofproto_parser

        if protocol_num in [1, 6, 17]:
            if is_spoofed:
                # In spoofing, source IP is not trusted.
                # Block/rate-limit by ingress port + destination + protocol.
                return parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=dst_ip,
                    ip_proto=protocol_num,
                )

            # Normal case: source IP is trusted enough to match.
            return parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip,
                ip_proto=protocol_num,
            )

        # Fallback for unknown IP protocol
        if is_spoofed:
            return parser.OFPMatch(
                in_port=in_port,
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=dst_ip,
            )

        return parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
        )

    def action_to_meter_id(self, strategy: str) -> Optional[int]:
        if strategy in self.METER_IDS:
            return self.METER_IDS[strategy]
        return None

    def apply_rate_limit(
        self,
        datapath,
        src_ip: str,
        dst_ip: str,
        out_port: int,
        in_port: int,
        protocol_num: int,
        is_spoofed: bool,
        strategy: str,
        rate_kbps: int,
    ):
        meter_id = self.action_to_meter_id(strategy)

        if meter_id is None:
            self.logger.warning("Unknown rate-limit strategy: %s", strategy)
            return

        match = self.build_defense_match(
            datapath=datapath,
            src_ip=src_ip,
            dst_ip=dst_ip,
            in_port=in_port,
            protocol_num=protocol_num,
            is_spoofed=is_spoofed,
        )

        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]

        self.add_flow(
            datapath=datapath,
            priority=200,
            match=match,
            actions=actions,
            meter_id=meter_id,
            idle_timeout=self.game_round_interval,
            hard_timeout=self.game_round_interval,
        )

        self.logger.warning(
            "RATE_LIMIT_APPLIED strategy=%s rate=%skbps src=%s dst=%s in_port=%s proto=%s spoofed=%s",
            strategy,
            rate_kbps,
            src_ip,
            dst_ip,
            in_port,
            self.get_protocol_name(protocol_num),
            is_spoofed,
        )

    def restore_default_rate(
        self,
        datapath,
        src_ip: str,
        dst_ip: str,
        out_port: int,
        in_port: Optional[int] = None,
        protocol_num: Optional[int] = None,
    ):
        parser = datapath.ofproto_parser

        matches = []

        if protocol_num is not None and protocol_num in [1, 6, 17]:
            # Normal source-based defense rule
            matches.append(
                parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                    ip_proto=protocol_num,
                )
            )

            # Spoofing port-based defense rule
            if in_port is not None:
                matches.append(
                    parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_dst=dst_ip,
                        ip_proto=protocol_num,
                    )
                )
        else:
            matches.append(
                parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                )
            )

        for match in matches:
            self.delete_flow(datapath, match)

    def apply_block(
        self,
        datapath,
        src_ip: str,
        dst_ip: str,
        in_port: int,
        protocol_num: int,
        is_spoofed: bool,
    ):
        """
        Install a high-priority OpenFlow drop rule.
        Empty instruction list means drop.
        """
        parser = datapath.ofproto_parser

        match = self.build_defense_match(
            datapath=datapath,
            src_ip=src_ip,
            dst_ip=dst_ip,
            in_port=in_port,
            protocol_num=protocol_num,
            is_spoofed=is_spoofed,
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=300,
            match=match,
            instructions=[],
            idle_timeout=self.block_idle_timeout,
            hard_timeout=0,
        )

        datapath.send_msg(mod)

        self.logger.warning(
            "BLOCK_RULE_INSTALLED src=%s dst=%s in_port=%s proto=%s spoofed=%s idle_timeout=%s",
            src_ip,
            dst_ip,
            in_port,
            self.get_protocol_name(protocol_num),
            is_spoofed,
            self.block_idle_timeout,
        )

    # ------------------------------------------------------------------
    # Snort alert handling
    # ------------------------------------------------------------------

    def parse_alert_timestamp(self, line: str) -> Optional[datetime]:
        try:
            ts = line[:19]
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None

    def line_is_recent(self, line: str) -> bool:
        ts = self.parse_alert_timestamp(line)

        # If no timestamp exists, treat the alert as valid.
        if ts is None:
            return True

        return (datetime.now() - ts).total_seconds() <= self.snort_alert_window_sec

    def has_recent_snort_alert(self, src_ip: str, dst_ip: str) -> bool:
        """
        Reads the last Snort alert lines.
        Supports custom project lines such as:
            2026-05-07 10:00:00 PROJECT_ICMP_ATTACK src=10.0.0.1 dst=10.0.0.2

        Also supports simple testing lines such as:
            SNORT_REAL_ICMP ICMP Flood Alert
        """
        if not os.path.exists(self.snort_alert_log):
            return False

        try:
            with open(self.snort_alert_log, "r", encoding="utf-8", errors="ignore") as f:
                recent_lines = deque(f, maxlen=300)

            for line in reversed(recent_lines):
                line_upper = line.upper()

                if not self.line_is_recent(line):
                    continue

                has_project_marker = "PROJECT_ICMP_ATTACK" in line_upper
                has_snort_marker = "SNORT_REAL_ICMP" in line_upper
                has_icmp_alert = "ICMP" in line_upper and "ALERT" in line_upper

                if not (has_project_marker or has_snort_marker or has_icmp_alert):
                    continue

                forward_match = f"src={src_ip}" in line and f"dst={dst_ip}" in line
                reverse_match = f"src={dst_ip}" in line and f"dst={src_ip}" in line

                # If the alert has exact src/dst, use it.
                if forward_match or reverse_match:
                    return True

                # If it is a general ICMP alert without IP fields, accept it for the demo.
                if has_snort_marker and "SRC=" not in line_upper and "DST=" not in line_upper:
                    return True

            return False

        except Exception as e:
            self.logger.error("Error while reading Snort alerts: %s", e)
            return False

    # ------------------------------------------------------------------
    # Round-based monitoring
    # ------------------------------------------------------------------

    def record_flow_stats(
        self,
        flow_key,
        datapath,
        out_port,
        in_port=None,
        protocol="OTHER",
        is_spoofed=False,
    ):
        now = time.time()

        if flow_key not in self.flow_stats:
            self.flow_stats[flow_key] = {
                "packet_count": 0,
                "last_seen": now,
                "datapath": datapath,
                "out_port": out_port,
                "in_port": in_port,
                "protocol": protocol,
                "is_spoofed": is_spoofed,
            }

        self.flow_stats[flow_key]["packet_count"] += 1
        self.flow_stats[flow_key]["last_seen"] = now
        self.flow_stats[flow_key]["datapath"] = datapath
        self.flow_stats[flow_key]["out_port"] = out_port
        self.flow_stats[flow_key]["in_port"] = in_port
        self.flow_stats[flow_key]["protocol"] = protocol
        self.flow_stats[flow_key]["is_spoofed"] = is_spoofed

    def game_round_loop(self):
        while True:
            try:
                self.evaluate_game_round()
            except Exception as e:
                self.logger.error("Game round loop error: %s", e)
            hub.sleep(self.game_round_interval)

    def force_critical_block_if_needed(
        self,
        engine_strategy: str,
        engine_rate_kbps: int,
        protocol: str,
        packet_rate_pps: float,
        snort_alert: bool,
        is_spoofed: bool,
    ):
        """
        The game engine is the main decision maker.
        This function only guarantees BLOCK in clearly critical cases
        so the practical demo shows the drop rule when the attack is severe.
        """
        protocol = str(protocol).upper()

        if (
            protocol == "ICMP"
            and is_spoofed
            and snort_alert
            and packet_rate_pps >= self.critical_spoofed_icmp_pps
        ):
            return "BLOCK", 0, "CRITICAL_SPOOFED_ICMP_FLOOD"

        if (
            protocol == "ICMP"
            and snort_alert
            and packet_rate_pps >= self.critical_icmp_pps
        ):
            return "BLOCK", 0, "CRITICAL_ICMP_FLOOD"

        return engine_strategy, engine_rate_kbps, "GAME_ENGINE_DECISION"

    def evaluate_game_round(self):
        now = time.time()
        stale_keys = []

        for flow_key, stats in list(self.flow_stats.items()):
            src_ip, dst_ip = flow_key

            packet_count = stats.get("packet_count", 0)
            datapath = stats.get("datapath")
            out_port = stats.get("out_port")
            in_port = stats.get("in_port")
            protocol = stats.get("protocol", "OTHER")
            is_spoofed = stats.get("is_spoofed", False)
            last_seen = stats.get("last_seen", now)

            if datapath is None or out_port is None:
                continue

            if in_port is None:
                continue

            protocol_num = self.protocol_name_to_num(protocol)

            packet_rate_pps = packet_count / float(self.game_round_interval)
            snort_alert = self.has_recent_snort_alert(src_ip, dst_ip)

            # Fallback values if exact measurement is not implemented yet
            packet_loss_pct = self.last_packet_loss.get(flow_key, 0.0)
            rtt_ms = self.last_rtt.get(flow_key, 5.0)

            obs = Observation(
                packet_rate_pps=packet_rate_pps,
                snort_alert=snort_alert,
                packet_loss_pct=packet_loss_pct,
                rtt_ms=rtt_ms,
                protocol=protocol,
                is_spoofed=is_spoofed,
            )

            decision = self.game_engine.choose_action(flow_key, obs)

            engine_strategy = decision["strategy"]
            engine_rate_kbps = decision["rate_kbps"]

            final_strategy, final_rate_kbps, reason = self.force_critical_block_if_needed(
                engine_strategy=engine_strategy,
                engine_rate_kbps=engine_rate_kbps,
                protocol=protocol,
                packet_rate_pps=packet_rate_pps,
                snort_alert=snort_alert,
                is_spoofed=is_spoofed,
            )

            if final_strategy == "ALLOW":
                self.restore_default_rate(
                    datapath=datapath,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    out_port=out_port,
                    in_port=in_port,
                    protocol_num=protocol_num,
                )

            elif final_strategy == "BLOCK":
                self.apply_block(
                    datapath=datapath,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    in_port=in_port,
                    protocol_num=protocol_num,
                    is_spoofed=is_spoofed,
                )

            else:
                self.apply_rate_limit(
                    datapath=datapath,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    out_port=out_port,
                    in_port=in_port,
                    protocol_num=protocol_num,
                    is_spoofed=is_spoofed,
                    strategy=final_strategy,
                    rate_kbps=final_rate_kbps,
                )

            beliefs = decision.get("beliefs", {})
            utilities = decision.get("utilities", {})

            self.logger.info(
                "GAME_DECISION src=%s dst=%s proto=%s in_port=%s spoofed=%s "
                "NORMAL=%.2f PROBE=%.2f FLOOD_LOW=%.2f FLOOD_HIGH=%.2f "
                "IP_SPOOFING=%.2f SPOOFED_FLOOD=%.2f "
                "U_ALLOW=%.2f U_RL1=%.2f U_RL2=%.2f U_RL3=%.2f U_BLOCK=%.2f "
                "engine_chosen=%s final_chosen=%s rate=%skbps reason=%s "
                "rep=%.2f round=%s snort=%s pps=%.2f",
                src_ip,
                dst_ip,
                protocol,
                in_port,
                is_spoofed,
                beliefs.get("NORMAL", 0.0),
                beliefs.get("PROBE", 0.0),
                beliefs.get("FLOOD_LOW", 0.0),
                beliefs.get("FLOOD_HIGH", 0.0),
                beliefs.get("IP_SPOOFING", 0.0),
                beliefs.get("SPOOFED_FLOOD", 0.0),
                utilities.get("ALLOW", 0.0),
                utilities.get("RL_1", 0.0),
                utilities.get("RL_2", 0.0),
                utilities.get("RL_3", 0.0),
                utilities.get("BLOCK", 0.0),
                engine_strategy,
                final_strategy,
                final_rate_kbps,
                reason,
                decision.get("reputation", 0.0),
                decision.get("round_count", 0),
                snort_alert,
                packet_rate_pps,
            )

            self.log_game_decision(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                in_port=in_port,
                packet_rate_pps=packet_rate_pps,
                snort_alert=snort_alert,
                is_spoofed=is_spoofed,
                engine_strategy=engine_strategy,
                final_strategy=final_strategy,
                rate_kbps=final_rate_kbps,
                decision=decision,
                reason=reason,
            )

            # Reset counter for next round
            self.flow_stats[flow_key]["packet_count"] = 0

            if now - last_seen > self.flow_stale_timeout:
                stale_keys.append(flow_key)

        for flow_key in stale_keys:
            self.flow_stats.pop(flow_key, None)
            self.game_engine.reset_flow(flow_key)

    # ------------------------------------------------------------------
    # Packet handling
    # ------------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match["in_port"]

        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src

        # Learn source MAC location
        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            protocol_num = ipv4_pkt.proto
            protocol_name = self.get_protocol_name(protocol_num)

            is_spoofed = self.is_spoofed_source(
                dpid=dpid,
                in_port=in_port,
                src_ip=src_ip,
            )

            flow_key = (src_ip, dst_ip)

            self.record_flow_stats(
                flow_key=flow_key,
                datapath=datapath,
                out_port=out_port,
                in_port=in_port,
                protocol=protocol_name,
                is_spoofed=is_spoofed,
            )

            if is_spoofed:
                self.logger.warning(
                    "IP_SPOOFING_DETECTED dpid=%s in_port=%s src_ip=%s dst_ip=%s expected_ip=%s",
                    dpid,
                    in_port,
                    src_ip,
                    dst_ip,
                    self.trusted_ip_by_port.get(dpid, {}).get(in_port),
                )

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
