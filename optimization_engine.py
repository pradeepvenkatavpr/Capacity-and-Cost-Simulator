from __future__ import annotations
import math
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence
from kubernetes_analyzer import KubernetesInventory, WorkloadRecord
from capacity_analyzer import CapacityFinding, CapacityReport
from cost_simulator import CostReport, CostSimulator

def _map(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}

def _num(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return result if math.isfinite(result) else default
    except (TypeError, ValueError):
        return default

def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))

@dataclass
class Recommendation:
    """Reviewable optimization proposal with score, risk, and validation plan."""
    recommendation_id: str
    category: str
    title: str
    description: str
    workload: dict[str, str]
    risk_level: str
    severity: str
    score: float
    score_components: dict[str, float]
    estimated_monthly_savings: dict[str, Any]
    capacity_impact: dict[str, Any]
    proposed_changes: list[dict[str, Any]]
    assumptions: list[str]
    validation_steps: list[str]
    requires_human_approval: bool
    auto_applicable: bool = False
    policy_rule_ids: list[str] = field(default_factory=list)

@dataclass
class OptimizationReport:
    """Ranked recommendations and summary counts."""
    recommendation_count: int
    recommendations: list[Recommendation]
    summary: dict[str, Any]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "recommendation_count": self.recommendation_count,
            "recommendations": [asdict(item) for item in self.recommendations],
            "summary": self.summary,
            "warnings": self.warnings,
        }

class OptimizationEngine:
    """Generate and rank recommendations without applying any Kubernetes change."""

    def __init__(
        self, config: Mapping[str, Any] | None = None,
        rules: Mapping[str, Any] | None = None,
        cost_policies: Mapping[str, Any] | None = None,
    ):
        self.config = dict(config or {})
        self.rules_doc = dict(rules or {})
        self.cost_policies = dict(cost_policies or {})
        self.optimization = _map(self.config.get("optimization"))
        self.recommendation_cfg = _map(self.optimization.get("recommendations"))
        self.scoring = _map(self.optimization.get("scoring"))
        self.risk = _map(self.optimization.get("risk"))
        self.currency = str(_map(self.config.get("cost")).get("currency", "USD"))
        self.minimum_score = _num(self.scoring.get("minimum_recommendation_score"), 0.30)
        self.max_recommendations = int(_map(self.config.get("policy")).get("maximum_recommendations", 100))
        self.cost_simulator = CostSimulator(self.config, self.cost_policies)
        self.warnings: list[str] = []

    def _weights(self) -> dict[str, float]:
        defaults = {"cost": 0.35, "capacity": 0.25, "reliability": 0.25, "effort": 0.15}
        configured = {
            "cost": _num(self.scoring.get("cost_savings_weight"), defaults["cost"]),
            "capacity": _num(self.scoring.get("capacity_efficiency_weight"), defaults["capacity"]),
            "reliability": _num(self.scoring.get("reliability_weight"), defaults["reliability"]),
            "effort": _num(self.scoring.get("implementation_effort_weight"), defaults["effort"]),
        }
        configured = {key: max(0.0, value) for key, value in configured.items()}
        total = sum(configured.values())
        return defaults if total <= 0 else {key: value / total for key, value in configured.items()}

    def _protected(self, workload: WorkloadRecord) -> bool:
        namespaces = set(self.risk.get("protected_namespaces", ["kube-system", "kube-public", "kube-node-lease"]))
        if workload.namespace in namespaces:
            return True
        labels = _map(self.risk.get("protected_labels"))
        return any(
            workload.labels.get(str(key)) == str(value) or workload.pod_labels.get(str(key)) == str(value)
            for key, value in labels.items()
        )

    def _risk(self, workload: WorkloadRecord, environment: str, category: str) -> tuple[str, bool]:
        if self._protected(workload):
            return "critical", True
        if workload.kind == "StatefulSet" and self.risk.get("stateful_workload_changes_require_review", True):
            return "high", True
        if environment == "production" and category in {"cpu_rightsizing", "memory_rightsizing", "scale_down"}:
            return ("high", True) if self.risk.get("production_scale_down_requires_review", True) else ("medium", True)
        if environment == "production":
            return "medium", True
        return "low", False

    def _score(
        self, savings: float | None, capacity: float, reliability: float, effort: float,
    ) -> tuple[float, dict[str, float]]:
        weights = self._weights()
        savings_score = 0 if savings is None else _clamp(math.log1p(max(0, savings)) / math.log1p(1000))
        components = {
            "cost_savings": _clamp(savings_score),
            "capacity_efficiency": _clamp(capacity),
            "reliability": _clamp(reliability),
            "implementation_effort": _clamp(effort),
        }
        score = sum(components[key] * weights[key] for key in components)
        return round(score, 4), {key: round(value, 4) for key, value in components.items()}

    def _make(
        self, workload: WorkloadRecord, rid: str, category: str, title: str, description: str,
        risk: str, severity: str, score: float, components: Mapping[str, float],
        savings: float | None, impact: Mapping[str, Any], proposed: Sequence[Mapping[str, Any]],
        assumptions: Sequence[str], validation: Sequence[str], approval: bool, rules: Sequence[str] = (),
    ) -> Recommendation:
        return Recommendation(
            recommendation_id=rid, category=category, title=title, description=description,
            workload={"namespace": workload.namespace, "name": workload.name, "kind": workload.kind},
            risk_level=risk, severity=severity, score=score, score_components=dict(components),
            estimated_monthly_savings={"amount": None if savings is None else round(savings, 2),
                                       "currency": self.currency, "estimated": True, "known": savings is not None},
            capacity_impact=dict(impact), proposed_changes=[dict(x) for x in proposed],
            assumptions=list(assumptions), validation_steps=list(validation),
            requires_human_approval=approval, auto_applicable=False, policy_rule_ids=list(rules),
        )

    def _container_recommendations(
        self, workload: WorkloadRecord, environment: str, metrics: Mapping[str, Any] | None,
    ) -> list[Recommendation]:
        if self._protected(workload):
            return []
        result = []
        record = _map((metrics or {}).get(f"{workload.namespace}/{workload.name}"))
        for container in workload.containers:
            if container.cpu_request_millicores is None and self.recommendation_cfg.get("detect_missing_requests_and_limits", True):
                risk, approval = self._risk(workload, environment, "cpu_rightsizing")
                score, parts = self._score(None, 0.5, 0.6, 0.8)
                result.append(self._make(
                    workload, f"REC-CPU-REQUEST-{workload.namespace}-{workload.name}-{container.name}",
                    "resource_declaration", f"Define CPU request for {container.name}",
                    "Set a CPU request after collecting representative demand metrics.",
                    risk, "high", score, parts, None, {"cpu_millicores_released": None},
                    [{"container": container.name, "field": "resources.requests.cpu", "proposed": "requires_metrics"}],
                    ["Manifest has no CPU request.", "A numeric request cannot be inferred safely from the manifest alone."],
                    ["Collect representative CPU metrics.", "Choose a percentile and safety margin.", "Test in staging.", "Monitor latency and throttling."],
                    approval, ["K8S001"],
                ))
            if container.memory_request_mib is None and self.recommendation_cfg.get("detect_missing_requests_and_limits", True):
                risk, approval = self._risk(workload, environment, "memory_rightsizing")
                score, parts = self._score(None, 0.4, 0.8, 0.7)
                result.append(self._make(
                    workload, f"REC-MEMORY-REQUEST-{workload.namespace}-{workload.name}-{container.name}",
                    "resource_declaration", f"Define memory request for {container.name}",
                    "Set a memory request using observed working-set and peak measurements.",
                    risk, "high", score, parts, None, {"memory_mib_released": None},
                    [{"container": container.name, "field": "resources.requests.memory", "proposed": "requires_metrics"}],
                    ["Manifest has no memory request.", "Memory sizing needs peak and working-set observations."],
                    ["Collect representative memory metrics.", "Include startup peaks and cache behavior.", "Review OOM events.", "Test the value in staging."],
                    approval, ["K8S002"],
                ))
            cpu_util = record.get("cpu_utilization_percent")
            if cpu_util is not None and container.cpu_request_millicores and _num(cpu_util, 1000) < 20:
                cpu_cfg = _map(_map(self.config.get("capacity")).get("cpu"))
                target = _num(cpu_cfg.get("target_utilization_percent"), 65)
                margin = _num(_map(_map(self.config.get("cost")).get("savings")).get("apply_safety_margin_percent"), 20)
                observed = container.cpu_request_millicores * _num(cpu_util) / 100
                proposed = max(_num(cpu_cfg.get("minimum_request_millicores"), 25), observed / max(target / 100, .01) * (1 + margin / 100))
                proposed = min(container.cpu_request_millicores, proposed)
                if proposed < container.cpu_request_millicores:
                    scenario = self.cost_simulator.compare_scenarios(workload, cpu_request_millicores=proposed)
                    savings = scenario["estimated_monthly_savings"]
                    risk, approval = self._risk(workload, environment, "cpu_rightsizing")
                    score, parts = self._score(savings, (container.cpu_request_millicores-proposed)/container.cpu_request_millicores, .35, .55)
                    result.append(self._make(
                        workload, f"REC-CPU-RIGHTSIZE-{workload.namespace}-{workload.name}-{container.name}",
                        "cpu_rightsizing", f"Review CPU request for {container.name}",
                        f"Observed CPU utilization is {_num(cpu_util):.1f}%; review a reduction with a safety margin.",
                        risk, "medium", score, parts, savings,
                        {"cpu_millicores_released_scenario": round(container.cpu_request_millicores-proposed, 2)},
                        [{"container": container.name, "field": "resources.requests.cpu",
                          "current_millicores": container.cpu_request_millicores, "proposed_millicores": round(proposed, 2)}],
                        ["Metric window may hide bursts.", "Cost uses configured rates and is a scenario."],
                        ["Validate metric freshness and percentiles.", "Review throttling and latency.", "Test in staging.", "Monitor after rollout."],
                        approval, ["K8S007", "K8S017", "K8S020"],
                    ))
            memory_util = record.get("memory_utilization_percent")
            if memory_util is not None and container.memory_request_mib and _num(memory_util, 1000) < 25:
                mem_cfg = _map(_map(self.config.get("capacity")).get("memory"))
                target = _num(mem_cfg.get("target_utilization_percent"), 70)
                margin = _num(_map(_map(self.config.get("cost")).get("savings")).get("apply_safety_margin_percent"), 20)
                observed = container.memory_request_mib * _num(memory_util) / 100
                proposed = max(_num(mem_cfg.get("minimum_request_mib"), 32), observed / max(target/100, .01) * (1 + margin/100))
                proposed = min(container.memory_request_mib, proposed)
                if proposed < container.memory_request_mib:
                    scenario = self.cost_simulator.compare_scenarios(workload, memory_request_mib=proposed)
                    savings = scenario["estimated_monthly_savings"]
                    risk, approval = self._risk(workload, environment, "memory_rightsizing")
                    score, parts = self._score(savings, (container.memory_request_mib-proposed)/container.memory_request_mib, .25, .45)
                    result.append(self._make(
                        workload, f"REC-MEMORY-RIGHTSIZE-{workload.namespace}-{workload.name}-{container.name}",
                        "memory_rightsizing", f"Review memory request for {container.name}",
                        f"Observed memory utilization is {_num(memory_util):.1f}%; validate request sizing against peaks.",
                        risk, "high", score, parts, savings,
                        {"memory_mib_released_scenario": round(container.memory_request_mib-proposed, 2)},
                        [{"container": container.name, "field": "resources.requests.memory",
                          "current_mib": container.memory_request_mib, "proposed_mib": round(proposed, 2)}],
                        ["Memory peaks and cache behavior must be considered.", "Savings are estimates."],
                        ["Review p95/p99 memory and OOM events.", "Test in staging.", "Roll out gradually.", "Monitor restarts."],
                        approval, ["K8S008", "K8S017", "K8S020"],
                    ))
        return result

    def _replica_recommendations(self, workload: WorkloadRecord, environment: str) -> list[Recommendation]:
        if self._protected(workload):
            return []
        result = []
        if workload.kind == "Deployment" and workload.desired_replicas < 2 and environment == "production":
            score, parts = self._score(None, .1, .95, .5)
            result.append(self._make(
                workload, f"REC-REPLICA-AVAILABILITY-{workload.namespace}-{workload.name}",
                "reliability", "Review production replica availability",
                "Confirm whether the workload needs redundancy across pod or node failures.",
                "high", "high", score, parts, None, {"desired_replicas": workload.desired_replicas},
                [{"field": "spec.replicas", "current": workload.desired_replicas, "proposed": "owner_review"}],
                ["Additional replicas increase allocated resources.", "Application state may constrain scaling."],
                ["Review SLO and probes.", "Check node spread and PDB.", "Load-test before rollout."],
                True, ["K8S011"],
            ))
        if workload.kind == "Deployment" and self.recommendation_cfg.get("recommend_hpa", True):
            score, parts = self._score(None, .6, .55, .45)
            result.append(self._make(
                workload, f"REC-HPA-REVIEW-{workload.namespace}-{workload.name}",
                "autoscaling", "Evaluate HorizontalPodAutoscaler",
                "Review whether variable demand would benefit from metric-driven replica scaling.",
                "medium" if environment == "production" else "low", "low", score, parts, None,
                {"autoscaling_candidate": True},
                [{"resource": "HorizontalPodAutoscaler", "status": "proposal_only"}],
                ["HPA needs a metrics source and realistic bounds.", "No manifest is applied by this tool."],
                ["Confirm metrics-server or adapter.", "Set min/max replicas.", "Test stabilization.", "Monitor SLOs."],
                environment == "production", ["K8S013"],
            ))
        return result

    def _finding_recommendations(
        self, inventory: KubernetesInventory, capacity: CapacityReport, environment: str,
    ) -> list[Recommendation]:
        result = []
        workloads = {(w.namespace, w.name): w for w in inventory.workloads}
        for finding in capacity.findings:
            key = (finding.workload["namespace"], finding.workload["name"])
            workload = workloads.get(key)
            if not workload or self._protected(workload):
                continue
            if finding.severity not in {"high", "critical"} and finding.rule_id not in {"K8S014", "K8S015"}:
                continue
            risk, approval = self._risk(workload, environment, finding.category)
            score, parts = self._score(None, .3, .9 if finding.severity in {"high", "critical"} else .6, .6)
            result.append(self._make(
                workload, f"REC-{finding.rule_id}-{workload.namespace}-{workload.name}",
                finding.category, finding.rule_name.replace("_", " ").title(), finding.message,
                risk if finding.severity not in {"critical"} else "critical", finding.severity,
                score, parts, None, finding.estimated_impact,
                [{"status": "review_required", "recommendation": finding.recommendation}],
                [finding.rationale],
                ["Review with workload owner.", "Validate in non-production.", "Monitor health after approved change."],
                approval or finding.severity in {"high", "critical"}, [finding.rule_id],
            ))
        return result

    def optimize(
        self, *, inventory: KubernetesInventory, capacity: CapacityReport, cost: CostReport,
        environment: str, metrics: Mapping[str, Any] | None = None,
    ) -> OptimizationReport:
        """Create a deterministic, deduplicated, risk-aware recommendation list."""
        self.warnings = []
        if not self.optimization.get("enabled", True):
            return OptimizationReport(0, [], {"enabled": False}, [])
        recommendations = []
        for workload in inventory.workloads:
            recommendations.extend(self._container_recommendations(workload, environment, metrics))
            recommendations.extend(self._replica_recommendations(workload, environment))
        recommendations.extend(self._finding_recommendations(inventory, capacity, environment))
        unique: dict[str, Recommendation] = {}
        for item in recommendations:
            if item.recommendation_id not in unique or item.score > unique[item.recommendation_id].score:
                unique[item.recommendation_id] = item
        ranked = [
            item for item in unique.values()
            if item.score >= self.minimum_score or item.severity in {"high", "critical"}
        ]
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        ranked.sort(key=lambda item: (-item.score, -severity_order.get(item.severity, 0),
                                      item.workload["namespace"], item.workload["name"], item.recommendation_id))
        if len(ranked) > self.max_recommendations:
            self.warnings.append(f"Recommendations truncated at configured maximum {self.max_recommendations}.")
            ranked = ranked[:self.max_recommendations]
        known = [item.estimated_monthly_savings["amount"] for item in ranked
                 if item.estimated_monthly_savings["known"] and item.estimated_monthly_savings["amount"] is not None]
        summary = {
            "enabled": True, "environment": environment, "recommendation_count": len(ranked),
            "by_category": {category: sum(x.category == category for x in ranked)
                            for category in sorted({x.category for x in ranked})},
            "by_risk": {risk: sum(x.risk_level == risk for x in ranked) for risk in ["critical", "high", "medium", "low"]},
            "requiring_human_approval": sum(x.requires_human_approval for x in ranked),
            "automatically_applicable": 0,
            "known_recommendation_savings_total": round(sum(known), 2) if known else None,
            "currency": self.currency,
            "score_interpretation": "Prioritization score, not probability of success.",
        }
        if not capacity.metrics_available:
            self.warnings.append("No metrics supplied; numerical right-sizing recommendations are limited.")
        if not cost.estimated_monthly_savings.known:
            self.warnings.append("Aggregate savings are unknown because one or more costs are incomplete.")
        return OptimizationReport(len(ranked), ranked, summary, sorted(set(self.warnings)))

    def explain(self, recommendation: Recommendation) -> dict[str, Any]:
        """Create an explanation payload for a dashboard or pull-request comment."""
        return {
            "recommendation_id": recommendation.recommendation_id,
            "title": recommendation.title,
            "score": recommendation.score,
            "score_components": recommendation.score_components,
            "risk_level": recommendation.risk_level,
            "estimated_monthly_savings": recommendation.estimated_monthly_savings,
            "validation_steps": recommendation.validation_steps,
            "requires_human_approval": recommendation.requires_human_approval,
            "auto_applicable": False,
            "assumptions": recommendation.assumptions,
        }


"""
Implementation and operator reference
=====================================

1. Recommendation evidence
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

2. Ranking score interpretation
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

3. Weighted scoring
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

4. Cost benefit dimension
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

5. Capacity efficiency dimension
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

6. Reliability dimension
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

7. Implementation effort dimension
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

8. Production approval
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

9. Stateful workload approval
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

10. Protected namespace exclusions
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

11. CPU right-sizing math
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

12. Memory right-sizing math
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

13. Missing request recommendations
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

14. HPA evaluation
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

15. Replica availability
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

16. Deduplication
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

17. Maximum recommendation count
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

18. Stable ranking order
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

19. Unknown savings handling
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

20. Business value reporting
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

21. Validation steps
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

22. Owner review
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

23. Canary rollout
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

24. Rollback criteria
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

25. Metrics feedback loop
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

26. Actual invoice comparison
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

27. Recommendation acceptance tracking
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

28. Policy tuning
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

29. Safety boundaries
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

30. CI integration
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

31. No automatic patching
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

32. Limitations
   Recommendations should be actionable, evidence-based, explainable, and non-mutating. Rank by several business dimensions, but never let a high score override safety policy, production review, or protected-resource rules.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

"""
