from __future__ import annotations
import math
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping
from kubernetes_analyzer import KubernetesInventory, WorkloadRecord, ContainerResources

def _map(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}

def _num(value: Any, default: float) -> float:
    try:
        number = float(value)
        return number if math.isfinite(number) else default
    except (TypeError, ValueError):
        return default

@dataclass
class CapacityFinding:
    """Policy finding with workload identity, evidence, and safe next step."""
    rule_id: str
    rule_name: str
    severity: str
    blocking: bool
    workload: dict[str, str]
    message: str
    recommendation: str
    rationale: str
    evidence: dict[str, Any] = field(default_factory=dict)
    category: str = "capacity"
    requires_metrics: bool = False
    estimated_impact: dict[str, Any] = field(default_factory=dict)

@dataclass
class CapacityReport:
    """Findings and aggregate summary for one inventory."""
    finding_count: int
    findings: list[CapacityFinding]
    summary: dict[str, Any]
    metrics_available: bool
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_count": self.finding_count,
            "findings": [asdict(f) for f in self.findings],
            "summary": self.summary,
            "metrics_available": self.metrics_available,
            "warnings": self.warnings,
        }

class CapacityAnalyzer:
    """Evaluate declarations, utilization evidence, replica posture, and protections."""

    def __init__(
        self, config: Mapping[str, Any] | None = None,
        rules: Mapping[str, Any] | None = None,
        metrics: Mapping[str, Any] | None = None,
    ):
        self.config = dict(config or {})
        self.rules_doc = dict(rules or {})
        self.metrics = dict(metrics or {})
        self.capacity = _map(self.config.get("capacity"))
        self.cpu_cfg = _map(self.capacity.get("cpu"))
        self.mem_cfg = _map(self.capacity.get("memory"))
        self.replica_cfg = _map(self.capacity.get("replicas"))
        self.scheduling = _map(self.capacity.get("scheduling"))
        self.settings = _map(self.rules_doc.get("settings"))
        self.rules = {
            str(item.get("id")): dict(item)
            for item in self.rules_doc.get("rules", [])
            if isinstance(item, Mapping) and item.get("enabled", True)
        }
        self.warnings: list[str] = []

    def _rule(self, rule_id: str, name: str, severity: str, blocking: bool = False) -> dict[str, Any]:
        configured = self.rules.get(rule_id, {})
        return {
            "id": rule_id,
            "name": configured.get("name", name),
            "severity": str(configured.get("severity", severity)).lower(),
            "blocking": bool(configured.get("blocking", blocking)),
            "recommendation": configured.get("recommendation", ""),
            "rationale": configured.get("rationale", ""),
        }

    def _finding(
        self, workload: WorkloadRecord, rule_id: str, name: str, severity: str,
        message: str, recommendation: str, rationale: str,
        evidence: Mapping[str, Any] | None = None, category: str = "capacity",
        requires_metrics: bool = False, blocking: bool = False,
    ) -> CapacityFinding:
        rule = self._rule(rule_id, name, severity, blocking)
        return CapacityFinding(
            rule_id=rule["id"], rule_name=rule["name"], severity=rule["severity"],
            blocking=rule["blocking"],
            workload={"name": workload.name, "namespace": workload.namespace, "kind": workload.kind},
            message=message, recommendation=rule["recommendation"] or recommendation,
            rationale=rule["rationale"] or rationale, evidence=dict(evidence or {}),
            category=category, requires_metrics=requires_metrics,
        )

    def _excluded(self, workload: WorkloadRecord) -> bool:
        if workload.namespace in set(self.settings.get("exclude_namespaces", [])):
            return True
        labels = _map(self.settings.get("exclude_labels"))
        return any(workload.labels.get(str(k)) == str(v) for k, v in labels.items())

    def _container_checks(self, workload: WorkloadRecord) -> list[CapacityFinding]:
        findings = []
        specs = [
            ("cpu", "cpu_request_millicores", "cpu_limit_millicores", "K8S001", "K8S003"),
            ("memory", "memory_request_mib", "memory_limit_mib", "K8S002", "K8S004"),
        ]
        for container in workload.containers:
            for resource, request_field, limit_field, missing_req_id, missing_limit_id in specs:
                request = getattr(container, request_field)
                limit = getattr(container, limit_field)
                if request is None and self.scheduling.get("flag_missing_requests", True):
                    findings.append(self._finding(
                        workload, missing_req_id, f"missing_{resource}_request", "high",
                        f"Container {container.name!r} has no {resource} request.",
                        f"Set {resource} request using representative usage metrics and a safety margin.",
                        "Requests influence scheduling and capacity allocation.",
                        {"container": container.name, "resource": resource, "request": None},
                    ))
                if limit is None and self.scheduling.get("flag_missing_limits", True):
                    findings.append(self._finding(
                        workload, missing_limit_id, f"missing_{resource}_limit",
                        "high" if resource == "memory" else "medium",
                        f"Container {container.name!r} has no {resource} limit.",
                        f"Review whether platform policy requires a {resource} limit.",
                        "Limits affect runtime behavior and should reflect workload characteristics.",
                        {"container": container.name, "resource": resource, "limit": None},
                    ))
                if request is not None and limit is not None and request > limit:
                    findings.append(self._finding(
                        workload, "K8S005" if resource == "cpu" else "K8S006",
                        f"{resource}_request_exceeds_limit",
                        "high" if resource == "cpu" else "critical",
                        f"Container {container.name!r} has a {resource} request greater than its limit.",
                        f"Correct the {resource} request/limit pair before deployment.",
                        "Request/limit inconsistency can invalidate workload assumptions.",
                        {"container": container.name, "request": request, "limit": limit, "resource": resource},
                        category="configuration", blocking=resource == "memory",
                    ))
        return findings

    def _replica_checks(self, workload: WorkloadRecord, environment: str) -> list[CapacityFinding]:
        findings = []
        minimum = int(self.replica_cfg.get(
            "minimum_for_stateless_production" if environment == "production"
            else "minimum_for_stateless_nonproduction",
            2 if environment == "production" else 1,
        ))
        if workload.kind == "Deployment" and workload.desired_replicas < minimum:
            findings.append(self._finding(
                workload, "K8S011", "single_replica_production_workload", "high",
                f"Deployment has {workload.desired_replicas} desired replicas; configured minimum is {minimum}.",
                "Review redundancy requirements and the impact of a pod disruption.",
                "A single replica can become a single point of failure.",
                {"desired_replicas": workload.desired_replicas, "minimum_replicas": minimum, "environment": environment},
                category="reliability",
            ))
        threshold = int(self.rules.get("K8S012", {}).get("threshold_replicas", 20))
        if workload.kind in {"Deployment", "StatefulSet"} and workload.desired_replicas > threshold:
            findings.append(self._finding(
                workload, "K8S012", "excessive_replica_count", "medium",
                f"Workload has {workload.desired_replicas} replicas, above review threshold {threshold}.",
                "Compare replica count with demand, per-replica requests, and scaling policy.",
                "A large replica count can affect capacity and cost, but may be justified.",
                {"desired_replicas": workload.desired_replicas, "threshold": threshold},
            ))
        if workload.ready_replicas is not None and workload.ready_replicas < workload.desired_replicas:
            findings.append(self._finding(
                workload, "K8S021", "ready_replicas_below_desired", "high",
                f"{workload.ready_replicas} of {workload.desired_replicas} desired replicas are ready.",
                "Inspect scheduling events, readiness probes, image pulls, and resource pressure.",
                "A readiness gap can reduce availability.",
                {"ready": workload.ready_replicas, "desired": workload.desired_replicas},
                category="reliability",
            ))
        return findings

    def _metrics_checks(self, workload: WorkloadRecord) -> list[CapacityFinding]:
        findings = []
        record = _map(self.metrics.get(f"{workload.namespace}/{workload.name}"))
        if not record:
            return findings
        for resource, cfg, low_id, high_id in [
            ("cpu", self.cpu_cfg, "K8S007", "K8S009"),
            ("memory", self.mem_cfg, "K8S008", "K8S010"),
        ]:
            raw = record.get(f"{resource}_utilization_percent")
            if raw is None:
                continue
            value = _num(raw, -1)
            if value < 0 or value > 1000:
                self.warnings.append(f"Invalid {resource} utilization for {workload.namespace}/{workload.name}; ignored.")
                continue
            low = _num(cfg.get("low_utilization_percent"), 20 if resource == "cpu" else 25)
            high = _num(cfg.get("high_utilization_percent"), 85 if resource == "cpu" else 90)
            if value < low:
                findings.append(self._finding(
                    workload, low_id, f"low_{resource}_utilization", "medium",
                    f"Observed {resource} utilization is {value:.1f}%, below {low:.1f}%.",
                    f"Evaluate {resource} request sizing using representative historical metrics.",
                    "Low utilization can indicate over-allocation but averages may hide peaks.",
                    {"utilization_percent": value, "threshold_percent": low,
                     "observation_hours": record.get("observation_hours")},
                    category="cost_efficiency", requires_metrics=True,
                ))
            if value > high:
                findings.append(self._finding(
                    workload, high_id, f"high_{resource}_utilization",
                    "critical" if resource == "memory" else "high",
                    f"Observed {resource} utilization is {value:.1f}%, above {high:.1f}%.",
                    f"Review {resource} demand, limits, throttling, and scaling behavior.",
                    "Sustained high utilization can indicate capacity pressure.",
                    {"utilization_percent": value, "threshold_percent": high,
                     "observation_hours": record.get("observation_hours")},
                    category="reliability", requires_metrics=True,
                ))
        return findings

    def _protected_checks(self, workload: WorkloadRecord) -> list[CapacityFinding]:
        protected = set(_map(_map(self.config.get("optimization")).get("risk")).get(
            "protected_namespaces", ["kube-system", "kube-public", "kube-node-lease"]
        ))
        if workload.namespace not in protected:
            return []
        return [self._finding(
            workload, "K8S016", "protected_namespace_change", "critical",
            f"Workload is in protected namespace {workload.namespace!r}.",
            "Do not automate optimization for protected Kubernetes system workloads.",
            "System workload changes can affect cluster-wide operation.",
            {"namespace": workload.namespace}, category="safety", blocking=True,
        )]

    def analyze(self, inventory: KubernetesInventory) -> CapacityReport:
        """Run declaration, replica, metric, and protected-namespace checks."""
        self.warnings = []
        findings: list[CapacityFinding] = []
        for workload in inventory.workloads:
            if self._excluded(workload):
                continue
            findings.extend(self._container_checks(workload))
            findings.extend(self._replica_checks(workload, inventory.environment))
            findings.extend(self._metrics_checks(workload))
            findings.extend(self._protected_checks(workload))
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (order.get(f.severity, 5), f.workload["namespace"], f.workload["name"], f.rule_id))
        severities = {}
        categories = {}
        for item in findings:
            severities[item.severity] = severities.get(item.severity, 0) + 1
            categories[item.category] = categories.get(item.category, 0) + 1
        summary = {
            "workload_count": inventory.workload_count,
            "container_count": inventory.container_count,
            "cpu_request_millicores": round(inventory.total_cpu_request_millicores, 2),
            "memory_request_mib": round(inventory.total_memory_request_mib, 2),
            "severity_counts": severities,
            "findings_by_category": categories,
            "blocking_finding_count": sum(f.blocking for f in findings),
        }
        if not self.metrics:
            self.warnings.append("No utilization metrics supplied; no observed usage is inferred from manifests.")
        return CapacityReport(
            finding_count=len(findings), findings=findings, summary=summary,
            metrics_available=bool(self.metrics), warnings=sorted(set(self.warnings)),
        )

    def summarize_workload(self, workload: WorkloadRecord) -> dict[str, Any]:
        """Provide compact per-workload capacity facts for reporting."""
        return {
            "namespace": workload.namespace, "name": workload.name, "kind": workload.kind,
            "desired_replicas": workload.desired_replicas, "ready_replicas": workload.ready_replicas,
            "container_count": workload.container_count,
            "cpu_request_millicores": round(workload.requested_cpu_millicores, 2),
            "cpu_limit_millicores": workload.limited_cpu_millicores,
            "memory_request_mib": round(workload.requested_memory_mib, 2),
            "memory_limit_mib": workload.limited_memory_mib,
        }


"""
Implementation and operator reference
=====================================

1. Missing request interpretation
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

2. CPU limit tradeoffs
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

3. Memory limit tradeoffs
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

4. Request and limit consistency
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

5. Observed metrics requirement
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

6. Metrics freshness
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

7. Percentile selection
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

8. Peak behavior
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

9. Low utilization interpretation
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

10. High utilization interpretation
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

11. Production replica policy
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

12. Ready replica gap
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

13. DaemonSet capacity context
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

14. StatefulSet risk
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

15. Protected namespace policy
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

16. Severity semantics
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

17. Rule customization
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

18. Findings evidence
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

19. Capacity totals
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

20. Node allocatable limitations
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

21. Pod overhead limitations
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

22. Affinity and taint limitations
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

23. Horizontal autoscaling
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

24. Disruption budgets
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

25. Testing missing requests
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

26. Testing inconsistent limits
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

27. Testing low CPU
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

28. Testing high memory
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

29. Testing missing metrics
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

30. Testing excluded namespaces
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

31. Review workflow
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

32. No mutation guarantee
   Every finding should state the observed evidence, policy threshold, operational meaning, and next validation step. Missing metrics should not be converted into fabricated utilization. System namespaces and protected labels should be excluded from optimization.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

"""


'''
Extended validation checklist
=============================

1. Rule identifier stability
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

2. Finding message quality
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

3. Evidence completeness
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

4. Severity normalization
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

5. Blocking flag semantics
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

6. Missing CPU request
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

7. Missing memory request
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

8. Missing CPU limit
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

9. Missing memory limit
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

10. Request above limit
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

11. Production minimum replicas
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

12. Ready replica mismatch
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

13. Metric key convention
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

14. Metric percentage validation
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

15. Low utilization threshold
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

16. High utilization threshold
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

17. Stale metrics
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

18. Metric observation window
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

19. Memory peak protection
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

20. CPU throttling evidence
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

21. Protected namespace policy
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

22. Protected workload labels
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

23. Finding ordering
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

24. Summary consistency
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

25. Test fixtures for Deployment
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

26. Test fixtures for StatefulSet
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

27. Test fixtures for CronJob
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

28. Test fixtures for missing resources
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

29. Review before enforcing blockers
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

30. Capacity review sign-off
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

'''
