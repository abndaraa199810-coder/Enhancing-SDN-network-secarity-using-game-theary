import os
import time
import csv
import json
from datetime import datetime
from collections import deque
from typing import Dict, Tuple

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, ether_types

from game_engine_multistage import DynamicGameEngine, Observation


class RyuDDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

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

        self.ml_detection_path = "/tmp/ml_detection_latest.json"
        self.ml_confidence_threshold = 0.50

        self.flow_stats: Dict[Tuple[str, str], Dict] = {}
        self.last_rtt: Dict[Tuple[str, str], float] = {}
        self.last_packet_loss: Dict[Tuple[str, str], float] = {}

        self.game_round_interval = 3
        self.flow_stale_timeout = 20

        self.attack_memory_window = 15
        self.victim_stage_history: Dict[str, deque] = {}

        self.snort_alert_log = os.path.expanduser(
            "~/SDN-GameTheory-Security/logs/snort_alerts.log"
        )
        self.snort_alert_window_sec = 60

        self.block_idle_timeout = 30

        self.critical_icmp_pps = 1300.0
        self.critical_spoofed_icmp_pps = 300.0

        self.stage_probe_pps = 5.0
        self.stage_low_flood_pps = 30.0
        self.stage_high_flood_pps = 120.0

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
            },
        }

        self.known_host_ips = {
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3",
            "10.0.0.4",
            "10.0.0.5",
            "10.0.0.6",
        }

        self.project_dir = os.path.expanduser("~/SDN-GameTheory-Security")
        self.logs_dir = os.path.join(self.project_dir, "logs")
        os.makedirs(self.logs_dir, exist_ok=True)

        self.game_decisions_log = os.path.join(
            self.logs_dir,
            "game_decisions_multistage.csv"
        )

        self.init_game_decisions_log()

        self.monitor_thread = hub.spawn(self.game_round_loop)


    def load_ml_detection(self):
        try:
            if not os.path.exists(self.ml_detection_path):
                return None

            with open(self.ml_detection_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            attack_detected = bool(data.get("attack_detected", False))
            confidence = float(data.get("joint_confidence", 0.0))

            if not attack_detected:
                return None

            if confidence < self.ml_confidence_threshold:
                return None

            return {
                "attack_detected": attack_detected,
                "attack_family": str(data.get("attack_family", "Unknown")),
                "attack_subpattern": str(data.get("attack_subpattern", "Unknown")),
                "joint_confidence": confidence,
            }

        except Exception as e:
            self.logger.warning("Could not load ML detection: %s", e)
            return None

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
                "markov_previous_state",
                "markov_current_state",
                "observed_stage",
                "multi_stage_flag",
                "active_sources_count",
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
                "reason",
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
                decision.get("markov_previous_state", "NORMAL"),
                decision.get("markov_current_state", "NORMAL"),
                decision.get("observed_stage", "NORMAL"),
                int(bool(decision.get("multi_stage_flag", False))),
                int(decision.get("active_sources_count", 1)),
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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]

        self.add_flow(
            datapath=datapath,
            priority=0,
            match=match,
            actions=actions
        )

        for strategy, meter_id in self.METER_IDS.items():
            self.add_meter(
                datapath=datapath,
                meter_id=meter_id,
                rate_kbps=self.RATE_LIMITS_KBPS[strategy],
            )

        self.logger.info("Switch %s connected to controller", datapath.id)
        self.logger.info("Meters installed: RL_1, RL_2, RL_3")

    def add_meter(self, datapath, meter_id: int, rate_kbps: int):
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
        meter_id=None,
        idle_timeout: int = 0,
        hard_timeout: int = 0,
    ):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = []

        if meter_id is not None:
            instructions.append(
                parser.OFPInstructionMeter(meter_id)
            )

        instructions.append(
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
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

    def get_protocol_name(self, proto_num: int) -> str:
        return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, "OTHER")

    def protocol_name_to_num(self, protocol_name: str) -> int:
        return {
            "ICMP": 1,
            "TCP": 6,
            "UDP": 17,
        }.get(str(protocol_name).upper(), 0)

    def is_spoofed_source(self, dpid: int, in_port: int, src_ip: str) -> bool:
        expected_ip = self.trusted_ip_by_port.get(dpid, {}).get(in_port)

        if expected_ip is not None:
            return src_ip != expected_ip

        if src_ip.startswith("10.0.0.") and src_ip not in self.known_host_ips:
            return True

        return False

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
                return parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=dst_ip,
                    ip_proto=protocol_num,
                )

            return parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip,
                ip_proto=protocol_num,
            )

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

    def action_to_meter_id(self, strategy: str):
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
        in_port=None,
        protocol_num=None,
    ):
        parser = datapath.ofproto_parser

        matches = []

        if protocol_num is not None and protocol_num in [1, 6, 17]:
            matches.append(
                parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                    ip_proto=protocol_num,
                )
            )

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

    def parse_alert_timestamp(self, line: str):
        try:
            ts = line[:19]
            return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None

    def line_is_recent(self, line: str) -> bool:
        ts = self.parse_alert_timestamp(line)

        if ts is None:
            return True

        age = (datetime.now() - ts).total_seconds()
        return age <= self.snort_alert_window_sec

    def has_recent_snort_alert(self, src_ip: str, dst_ip: str) -> bool:
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

                if forward_match or reverse_match:
                    return True

                if has_snort_marker and "SRC=" not in line_upper and "DST=" not in line_upper:
                    return True

            return False

        except Exception as e:
            self.logger.error("Error while reading Snort alerts: %s", e)
            return False

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

    def count_active_sources_to_victim(self, dst_ip: str, now: float) -> int:
        sources = set()

        for flow_key, stats in self.flow_stats.items():
            src, dst = flow_key

            if dst != dst_ip:
                continue

            last_seen = stats.get("last_seen", 0.0)
            packet_count = stats.get("packet_count", 0)

            if now - last_seen <= self.attack_memory_window and packet_count > 0:
                sources.add(src)

        return max(len(sources), 1)

    def classify_observed_stage(
        self,
        protocol: str,
        packet_rate_pps: float,
        snort_alert: bool,
        is_spoofed: bool,
        active_sources_count: int,
    ) -> str:
        protocol = str(protocol).upper()

        if is_spoofed and (packet_rate_pps >= self.stage_probe_pps or snort_alert):
            return "SPOOFED_FLOOD"

        if is_spoofed:
            return "IP_SPOOFING"

        if active_sources_count >= 2 and (
            packet_rate_pps >= self.stage_probe_pps or snort_alert
        ):
            return "FLOOD_HIGH"

        if packet_rate_pps < self.stage_probe_pps and not snort_alert:
            return "NORMAL"

        if packet_rate_pps < self.stage_low_flood_pps and not snort_alert:
            return "PROBE"

        if packet_rate_pps < self.stage_high_flood_pps:
            return "FLOOD_LOW"

        return "FLOOD_HIGH"

    def get_previous_stage_for_victim(self, dst_ip: str, now: float) -> str:
        history = self.victim_stage_history.get(dst_ip)

        if not history:
            return "NORMAL"

        while history and now - history[0][0] > self.attack_memory_window:
            history.popleft()

        if not history:
            return "NORMAL"

        return history[-1][1]

    def is_multi_stage_transition(
        self,
        previous_stage: str,
        current_stage: str,
        is_spoofed: bool,
        active_sources_count: int,
    ) -> bool:
        previous_stage = str(previous_stage or "NORMAL").upper()
        current_stage = str(current_stage or "NORMAL").upper()

        flood_stages = {"FLOOD_LOW", "FLOOD_HIGH"}
        spoof_stages = {"IP_SPOOFING", "SPOOFED_FLOOD"}

        if previous_stage in flood_stages and current_stage in spoof_stages:
            return True

        if previous_stage in spoof_stages and current_stage in flood_stages:
            return True

        if previous_stage not in {"NORMAL", "PROBE"} and active_sources_count >= 2:
            return True

        if is_spoofed and active_sources_count >= 2:
            return True

        return False

    def remember_stage_for_victim(self, dst_ip: str, now: float, current_stage: str):
        if dst_ip not in self.victim_stage_history:
            self.victim_stage_history[dst_ip] = deque()

        history = self.victim_stage_history[dst_ip]
        history.append((now, current_stage))

        while history and now - history[0][0] > self.attack_memory_window:
            history.popleft()

    def force_critical_block_if_needed(
        self,
        engine_strategy: str,
        engine_rate_kbps: int,
        protocol: str,
        packet_rate_pps: float,
        snort_alert: bool,
        is_spoofed: bool,
        multi_stage_flag: bool = False,
        active_sources_count: int = 1,
    ):
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

        if multi_stage_flag and protocol == "ICMP" and is_spoofed:
            return "BLOCK", 0, "MULTI_STAGE_SPOOFED_FLOOD"

        if multi_stage_flag and active_sources_count >= 2 and snort_alert:
            return "BLOCK", 0, "MULTI_STAGE_DDOS_ESCALATION"

        if multi_stage_flag and engine_strategy in ["ALLOW", "RL_1", "RL_2"]:
            return "RL_3", 512, "MULTI_STAGE_ESCALATION_TO_RL3"

        return engine_strategy, engine_rate_kbps, "GAME_ENGINE_DECISION"

    def evaluate_game_round(self):
        now = time.time()
        stale_keys = []

        # Load latest ML detection
        ml_detection = self.load_ml_detection()

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

            active_sources_count = self.count_active_sources_to_victim(
                dst_ip,
                now
            )

            previous_stage = self.get_previous_stage_for_victim(
                dst_ip,
                now
            )

            current_stage = self.classify_observed_stage(
                protocol=protocol,
                packet_rate_pps=packet_rate_pps,
                snort_alert=snort_alert,
                is_spoofed=is_spoofed,
                active_sources_count=active_sources_count,
            )

            multi_stage_flag = self.is_multi_stage_transition(
                previous_stage=previous_stage,
                current_stage=current_stage,
                is_spoofed=is_spoofed,
                active_sources_count=active_sources_count,
            )

            # ML detection strengthens the multi-stage evidence
            if ml_detection is not None:
                multi_stage_flag = True

            self.remember_stage_for_victim(
                dst_ip,
                now,
                current_stage
            )

            packet_loss_pct = self.last_packet_loss.get(flow_key, 0.0)
            rtt_ms = self.last_rtt.get(flow_key, 5.0)

            obs = Observation(
                packet_rate_pps=packet_rate_pps,
                snort_alert=snort_alert,
                packet_loss_pct=packet_loss_pct,
                rtt_ms=rtt_ms,
                protocol=protocol,
                is_spoofed=is_spoofed,
                active_sources_count=active_sources_count,
                multi_stage_flag=multi_stage_flag,
                previous_stage=previous_stage,
                current_stage=current_stage,
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
                multi_stage_flag=multi_stage_flag,
                active_sources_count=active_sources_count,
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

            self.logger.info(
                "GAME_DECISION src=%s dst=%s proto=%s spoofed=%s "
                "prev_stage=%s current_stage=%s multi_stage=%s active_sources=%s "
                "engine=%s final=%s rate=%s reason=%s pps=%.2f snort=%s",
                src_ip,
                dst_ip,
                protocol,
                is_spoofed,
                previous_stage,
                current_stage,
                multi_stage_flag,
                active_sources_count,
                engine_strategy,
                final_strategy,
                final_rate_kbps,
                reason,
                packet_rate_pps,
                snort_alert,
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

            self.flow_stats[flow_key]["packet_count"] = 0

            if now - last_seen > self.flow_stale_timeout:
                stale_keys.append(flow_key)

        for flow_key in stale_keys:
            self.flow_stats.pop(flow_key, None)
            self.game_engine.reset_flow(flow_key)

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
