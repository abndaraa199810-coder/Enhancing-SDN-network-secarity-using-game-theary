from dataclasses import dataclass
from typing import Dict, Tuple, Any
import math


@dataclass
class Observation:
    packet_rate_pps: float
    snort_alert: bool
    packet_loss_pct: float
    rtt_ms: float

    protocol: str = "OTHER"
    is_spoofed: bool = False

    active_sources_count: int = 1
    multi_stage_flag: bool = False
    previous_stage: str = "NORMAL"
    current_stage: str = "NORMAL"


class DynamicGameEngine:
    def __init__(self) -> None:
        self.base_rate_pps = 50.0
        self.alpha = 0.30
        self.switch_cost = 0.30

        self.states = [
            "NORMAL",
            "PROBE",
            "FLOOD_LOW",
            "FLOOD_HIGH",
            "IP_SPOOFING",
            "SPOOFED_FLOOD",
        ]

        self.actions = ["ALLOW", "RL_1", "RL_2", "RL_3", "BLOCK"]

        self.action_to_rate = {
            "ALLOW": 10000,
            "RL_1": 4000,
            "RL_2": 1024,
            "RL_3": 512,
            "BLOCK": 0,
        }

        self.markov_transition = {
            "NORMAL": {
                "NORMAL": 0.80,
                "PROBE": 0.15,
                "FLOOD_LOW": 0.03,
                "FLOOD_HIGH": 0.01,
                "IP_SPOOFING": 0.01,
                "SPOOFED_FLOOD": 0.00,
            },
            "PROBE": {
                "NORMAL": 0.15,
                "PROBE": 0.45,
                "FLOOD_LOW": 0.25,
                "FLOOD_HIGH": 0.08,
                "IP_SPOOFING": 0.05,
                "SPOOFED_FLOOD": 0.02,
            },
            "FLOOD_LOW": {
                "NORMAL": 0.05,
                "PROBE": 0.10,
                "FLOOD_LOW": 0.45,
                "FLOOD_HIGH": 0.25,
                "IP_SPOOFING": 0.05,
                "SPOOFED_FLOOD": 0.10,
            },
            "FLOOD_HIGH": {
                "NORMAL": 0.03,
                "PROBE": 0.05,
                "FLOOD_LOW": 0.12,
                "FLOOD_HIGH": 0.55,
                "IP_SPOOFING": 0.05,
                "SPOOFED_FLOOD": 0.20,
            },
            "IP_SPOOFING": {
                "NORMAL": 0.03,
                "PROBE": 0.07,
                "FLOOD_LOW": 0.10,
                "FLOOD_HIGH": 0.10,
                "IP_SPOOFING": 0.50,
                "SPOOFED_FLOOD": 0.20,
            },
            "SPOOFED_FLOOD": {
                "NORMAL": 0.02,
                "PROBE": 0.03,
                "FLOOD_LOW": 0.05,
                "FLOOD_HIGH": 0.15,
                "IP_SPOOFING": 0.10,
                "SPOOFED_FLOOD": 0.65,
            },
        }
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

        self.flow_state: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def _init_flow(self, flow_key: Tuple[str, str]) -> None:
        if flow_key not in self.flow_state:
            self.flow_state[flow_key] = {
                "malicious_reputation": 0.10,
                "last_action": "ALLOW",
                "round_count": 0,
                "last_markov_state": "NORMAL",
            }

    def reset_flow(self, flow_key: Tuple[str, str]) -> None:
        if flow_key in self.flow_state:
            del self.flow_state[flow_key]

    @staticmethod
    def clamp(value: float, low: float, high: float) -> float:
        return max(low, min(high, value))

    def softmax(self, scores: Dict[str, float]) -> Dict[str, float]:
        max_score = max(scores.values())
        exp_scores = {}

        for key, value in scores.items():
            exp_scores[key] = math.exp(value - max_score)

        total = sum(exp_scores.values())

        if total <= 0:
            return {key: 1.0 / len(scores) for key in scores}

        return {key: value / total for key, value in exp_scores.items()}

    def normalize(self, values: Dict[str, float]) -> Dict[str, float]:
        total = sum(max(v, 0.0) for v in values.values())

        if total <= 0:
            return {key: 1.0 / len(values) for key in values}

        return {key: max(value, 0.0) / total for key, value in values.items()}

    def infer_evidence_beliefs(self, obs: Observation) -> Dict[str, float]:
        rate = max(obs.packet_rate_pps, 0.0)
        rate_ratio = rate / max(self.base_rate_pps, 1.0)

        alert = 1.0 if obs.snort_alert else 0.0
        spoof = 1.0 if obs.is_spoofed else 0.0
        icmp = 1.0 if str(obs.protocol).upper() == "ICMP" else 0.0
        multi = 1.0 if obs.multi_stage_flag else 0.0
        sources = max(obs.active_sources_count, 1)

        attack_strength = math.log1p(rate_ratio)

        scores = {
            "NORMAL": (
                2.5
                - 2.5 * attack_strength
                - 2.5 * alert
                - 3.0 * spoof
                - 2.0 * multi
            ),
            "PROBE": (
                0.3
                + 0.7 * attack_strength
                + 0.3 * alert
                - 0.5 * spoof
                - 0.4 * multi
            ),
            "FLOOD_LOW": (
                -1.0
                + 1.4 * attack_strength
                + 0.9 * alert
                + 0.4 * icmp
            ),
            "FLOOD_HIGH": (
                -2.0
                + 2.4 * attack_strength
                + 1.2 * alert
                + 0.5 * icmp
                + 0.6 * max(sources - 1, 0)
            ),
            "IP_SPOOFING": (
                -2.0
                + 3.0 * spoof
                + 0.3 * alert
                + 0.2 * attack_strength
            ),
            "SPOOFED_FLOOD": (
                -3.0
                + 3.0 * spoof
                + 1.8 * attack_strength
                + 1.3 * alert
                + 0.8 * icmp
                + 1.4 * multi
            ),
        }

        return self.softmax(scores)

    def apply_markov_memory(
        self,
        evidence_beliefs: Dict[str, float],
        obs: Observation,
    ) -> Dict[str, float]:

        previous_stage = str(obs.previous_stage or "NORMAL").upper()

        if previous_stage not in self.markov_transition:
            previous_stage = "NORMAL"

        transition_prior = self.markov_transition[previous_stage]

        combined = {}

        for state in self.states:
            combined[state] = (
                0.65 * evidence_beliefs.get(state, 0.0)
                + 0.35 * transition_prior.get(state, 0.0)
            )

        current_stage = str(obs.current_stage or "NORMAL").upper()

        if current_stage in combined:
            combined[current_stage] += 0.15

        if obs.multi_stage_flag:
            combined["NORMAL"] *= 0.20
            combined["PROBE"] *= 0.60
            combined["FLOOD_HIGH"] += 0.12
            combined["SPOOFED_FLOOD"] += 0.20

        if obs.active_sources_count >= 2:
            combined["FLOOD_HIGH"] += 0.10
            combined["SPOOFED_FLOOD"] += 0.05

        if obs.is_spoofed:
            combined["IP_SPOOFING"] += 0.08
            combined["SPOOFED_FLOOD"] += 0.12

        return self.normalize(combined)

    def infer_attacker_beliefs(self, obs: Observation) -> Dict[str, float]:
        evidence = self.infer_evidence_beliefs(obs)
        beliefs = self.apply_markov_memory(evidence, obs)
        return beliefs

    def update_reputation(
        self,
        flow_key: Tuple[str, str],
        beliefs: Dict[str, float],
    ) -> float:

        self._init_flow(flow_key)

        previous_reputation = self.flow_state[flow_key]["malicious_reputation"]
        malicious_probability = 1.0 - beliefs.get("NORMAL", 0.0)

        new_reputation = (
            (1.0 - self.alpha) * previous_reputation
            + self.alpha * malicious_probability
        )

        cooling = 0.25 * beliefs.get("NORMAL", 0.0)
        new_reputation = new_reputation - cooling

        new_reputation = self.clamp(new_reputation, 0.0, 1.0)

        self.flow_state[flow_key]["malicious_reputation"] = new_reputation

        return new_reputation

    def expected_defender_utilities(
        self,
        beliefs: Dict[str, float],
        reputation: float,
        last_action: str,
        obs: Observation,
    ) -> Dict[str, float]:

        utilities = {}

        for action in self.actions:
            utility = 0.0

            for state in self.states:
                utility += beliefs.get(state, 0.0) * self.defender_payoff[state][action]

            if action == "ALLOW":
                utility -= 1.2 * reputation
            elif action == "RL_1":
                utility += 0.8 * reputation
            elif action == "RL_2":
                utility += 1.6 * reputation
            elif action == "RL_3":
                utility += 2.2 * reputation
            elif action == "BLOCK":
                utility += 3.0 * reputation

            if obs.multi_stage_flag:
                if action == "RL_3":
                    utility += 1.2
                elif action == "BLOCK":
                    utility += 2.8

            if obs.active_sources_count >= 2:
                if action == "RL_3":
                    utility += 0.8
                elif action == "BLOCK":
                    utility += 1.6

            if action == "BLOCK" and reputation < 0.65 and not obs.multi_stage_flag:
                utility -= 2.5

            if action != last_action:
                utility -= self.switch_cost

            utilities[action] = utility

        return utilities

    @staticmethod
    def best_response(utilities: Dict[str, float]) -> str:
        return max(utilities, key=utilities.get)

    def choose_action(
        self,
        flow_key: Tuple[str, str],
        obs: Observation,
    ) -> Dict[str, Any]:

        self._init_flow(flow_key)

        beliefs = self.infer_attacker_beliefs(obs)

        reputation = self.update_reputation(
            flow_key=flow_key,
            beliefs=beliefs,
        )

        last_action = self.flow_state[flow_key]["last_action"]

        utilities = self.expected_defender_utilities(
            beliefs=beliefs,
            reputation=reputation,
            last_action=last_action,
            obs=obs,
        )

        strategy = self.best_response(utilities)
        rate_kbps = self.action_to_rate[strategy]

        markov_previous_state = str(obs.previous_stage or "NORMAL")
        markov_current_state = max(beliefs, key=beliefs.get)

        self.flow_state[flow_key]["last_action"] = strategy
        self.flow_state[flow_key]["last_markov_state"] = markov_current_state
        self.flow_state[flow_key]["round_count"] += 1

        return {
            "strategy": strategy,
            "rate_kbps": rate_kbps,
            "beliefs": beliefs,
            "utilities": utilities,
            "reputation": reputation,
            "round_count": self.flow_state[flow_key]["round_count"],
            "markov_previous_state": markov_previous_state,
            "markov_current_state": markov_current_state,
            "multi_stage_flag": bool(obs.multi_stage_flag),
            "active_sources_count": int(obs.active_sources_count),
            "observed_stage": str(obs.current_stage or "NORMAL"),
        }
