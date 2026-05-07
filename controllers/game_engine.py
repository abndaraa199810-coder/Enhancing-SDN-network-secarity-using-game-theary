from dataclasses import dataclass
from typing import Dict, Tuple, Any
import math


@dataclass
class Observation:
    packet_rate_pps: float
    snort_alert: bool
    packet_loss_pct: float
    rtt_ms: float

    # New fields for our implementation
    protocol: str = "OTHER"      # ICMP / TCP / UDP / OTHER
    is_spoofed: bool = False     # True if source IP does not match trusted port


class DynamicGameEngine:
    """
    Dynamic game-theoretic defense engine.

    Players:
        - Attacker
        - Defender (Ryu Controller)

    Attacker strategies:
        - NORMAL
        - PROBE
        - FLOOD_LOW
        - FLOOD_HIGH
        - IP_SPOOFING
        - SPOOFED_FLOOD

    Defender strategies:
        - ALLOW
        - RL_1
        - RL_2
        - RL_3
        - BLOCK
    """

    def __init__(self) -> None:
        # Baseline assumptions
        self.base_rate_pps = 50.0

        # Repeated-game parameters
        self.alpha = 0.30
        self.switch_cost = 0.30

        # Defender action -> bandwidth rate
        self.action_to_rate = {
            "ALLOW": 10000,
            "RL_1": 4000,
            "RL_2": 1024,
            "RL_3": 512,
            "BLOCK": 0,
        }

        # Defender payoff matrix
        # Higher value = better for defender
        self.defender_payoff = {
            "NORMAL": {
                "ALLOW": 12.0,
                "RL_1": 3.0,
                "RL_2": 0.0,
                "RL_3": -2.0,
                "BLOCK": -15.0,
            },
            "PROBE": {
                "ALLOW": 4.0,
                "RL_1": 7.0,
                "RL_2": 5.0,
                "RL_3": 2.0,
                "BLOCK": -3.0,
            },
            "FLOOD_LOW": {
                "ALLOW": -4.0,
                "RL_1": 7.0,
                "RL_2": 8.5,
                "RL_3": 5.0,
                "BLOCK": 4.0,
            },
            "FLOOD_HIGH": {
                "ALLOW": -12.0,
                "RL_1": 1.0,
                "RL_2": 7.0,
                "RL_3": 9.0,
                "BLOCK": 12.0,
            },
            "IP_SPOOFING": {
                "ALLOW": -6.0,
                "RL_1": 4.0,
                "RL_2": 8.0,
                "RL_3": 6.0,
                "BLOCK": 5.0,
            },
            "SPOOFED_FLOOD": {
                "ALLOW": -15.0,
                "RL_1": 0.0,
                "RL_2": 6.0,
                "RL_3": 9.0,
                "BLOCK": 14.0,
            },
        }

        # State per flow: (src_ip, dst_ip)
        self.flow_state: Dict[Tuple[str, str], Dict[str, Any]] = {}

    @staticmethod
    def clamp(value: float, low: float, high: float) -> float:
        return max(low, min(high, value))

    @staticmethod
    def sigmoid(x: float) -> float:
        if x >= 0:
            z = math.exp(-x)
            return 1.0 / (1.0 + z)
        z = math.exp(x)
        return z / (1.0 + z)

    def softmax(self, scores: Dict[str, float]) -> Dict[str, float]:
        max_score = max(scores.values())
        exp_scores = {k: math.exp(v - max_score) for k, v in scores.items()}
        total = sum(exp_scores.values())

        if total == 0:
            n = len(scores)
            return {k: 1.0 / n for k in scores}

        return {k: exp_scores[k] / total for k in exp_scores}

    def _init_flow(self, flow_key: Tuple[str, str]) -> None:
        if flow_key not in self.flow_state:
            self.flow_state[flow_key] = {
                "malicious_reputation": 0.10,
                "last_action": "ALLOW",
                "round_count": 0,
            }

    def reset_flow(self, flow_key: Tuple[str, str]) -> None:
        if flow_key in self.flow_state:
            del self.flow_state[flow_key]

    def infer_attacker_beliefs(self, obs: Observation) -> Dict[str, float]:
        """
        Estimate attacker strategy probabilities from current observations.
        """
        rate_ratio = max(obs.packet_rate_pps / max(self.base_rate_pps, 1e-6), 0.0)
        attack_strength = math.log1p(rate_ratio)

        alert_strength = 1.0 if obs.snort_alert else 0.0
        spoof_strength = 1.0 if obs.is_spoofed else 0.0
        icmp_strength = 1.0 if str(obs.protocol).upper() == "ICMP" else 0.0

        loss_signal = self.sigmoid((obs.packet_loss_pct - 5.0) / 5.0)
        rtt_signal = self.sigmoid((obs.rtt_ms - 20.0) / 10.0)
        quality_pressure = 0.5 * loss_signal + 0.5 * rtt_signal

        logits = {
            "NORMAL": (
                2.2
                - 2.4 * attack_strength
                - 2.6 * alert_strength
                - 2.5 * spoof_strength
                - 1.2 * quality_pressure
            ),
            "PROBE": (
                -0.3
                + 0.6 * attack_strength
                + 0.7 * alert_strength
                - 0.5 * spoof_strength
                - 0.2 * quality_pressure
            ),
            "FLOOD_LOW": (
                -1.2
                + 1.3 * attack_strength
                + 1.2 * alert_strength
                + 0.7 * quality_pressure
            ),
            "FLOOD_HIGH": (
                -2.2
                + 2.2 * attack_strength
                + 1.5 * alert_strength
                + 1.4 * quality_pressure
                + 0.5 * icmp_strength
            ),
            "IP_SPOOFING": (
                -2.0
                + 3.0 * spoof_strength
                + 0.5 * alert_strength
                + 0.3 * attack_strength
            ),
            "SPOOFED_FLOOD": (
                -3.0
                + 3.0 * spoof_strength
                + 1.5 * alert_strength
                + 1.8 * attack_strength
                + 0.8 * icmp_strength
            ),
        }

        beliefs = self.softmax(logits)

        total = sum(beliefs.values())
        if total > 0:
            beliefs = {k: v / total for k, v in beliefs.items()}

        return beliefs

    def update_reputation(
        self,
        flow_key: Tuple[str, str],
        beliefs: Dict[str, float]
    ) -> float:
        """
        Update malicious reputation as repeated-game memory.
        """
        self._init_flow(flow_key)

        prev_rep = self.flow_state[flow_key]["malicious_reputation"]
        current_malicious = 1.0 - beliefs["NORMAL"]

        new_rep = ((1.0 - self.alpha) * prev_rep) + (self.alpha * current_malicious)

        # Faster recovery when traffic looks normal again
        cooling = 0.25 * beliefs["NORMAL"]
        new_rep = new_rep - cooling

        new_rep = self.clamp(new_rep, 0.0, 1.0)

        self.flow_state[flow_key]["malicious_reputation"] = new_rep
        return new_rep

    def expected_defender_utilities(
        self,
        beliefs: Dict[str, float],
        reputation: float,
        last_action: str
    ) -> Dict[str, float]:
        """
        Expected utility of each defender action.
        """
        utilities: Dict[str, float] = {}

        for action in self.action_to_rate:
            u = 0.0

            for attacker_strategy, prob in beliefs.items():
                u += prob * self.defender_payoff[attacker_strategy][action]

            # Reputation pressure
            if action == "ALLOW":
                u -= 1.2 * reputation
            elif action == "RL_1":
                u += 0.8 * reputation
            elif action == "RL_2":
                u += 1.6 * reputation
            elif action == "RL_3":
                u += 2.2 * reputation
            elif action == "BLOCK":
                u += 3.0 * reputation

            # Avoid blocking unless the state is really suspicious
            if action == "BLOCK" and reputation < 0.65:
                u -= 2.5

            # Small switching cost to reduce oscillation
            if action != last_action:
                u -= self.switch_cost

            utilities[action] = u

        return utilities

    @staticmethod
    def best_response(utilities: Dict[str, float]) -> str:
        return max(utilities, key=utilities.get)

    def choose_action(
        self,
        flow_key: Tuple[str, str],
        obs: Observation
    ) -> Dict[str, Any]:
        """
        Main API used by the Ryu controller.
        """
        self._init_flow(flow_key)

        beliefs = self.infer_attacker_beliefs(obs)
        reputation = self.update_reputation(flow_key, beliefs)
        last_action = self.flow_state[flow_key]["last_action"]

        utilities = self.expected_defender_utilities(
            beliefs=beliefs,
            reputation=reputation,
            last_action=last_action,
        )

        strategy = self.best_response(utilities)
        rate_kbps = self.action_to_rate[strategy]

        self.flow_state[flow_key]["last_action"] = strategy
        self.flow_state[flow_key]["round_count"] += 1

        return {
            "strategy": strategy,
            "rate_kbps": rate_kbps,
            "beliefs": beliefs,
            "utilities": utilities,
            "reputation": reputation,
            "round_count": self.flow_state[flow_key]["round_count"],
        }
