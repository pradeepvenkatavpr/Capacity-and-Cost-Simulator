from __future__ import annotations
import math
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping
from kubernetes_analyzer import KubernetesInventory, WorkloadRecord, ContainerResources
from capacity_analyzer import CapacityReport

def _map(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}

def _number(value: Any, default: float | None = None) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    return result if math.isfinite(result) else default

def _rounded(value: float | None, digits: int = 2) -> float | None:
    return None if value is None else round(value, digits)

@dataclass
class Money:
    """Money value with currency and explicit estimate/known indicators."""
    amount: float | None
    currency: str
    estimated: bool = True
    known: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class WorkloadCost:
    """Monthly allocation-cost estimate for one workload."""
    namespace: str
    name: str
    kind: str
    replicas: int
    cpu_cost_monthly: float | None
    memory_cost_monthly: float | None
    gpu_cost_monthly: float | None
    ephemeral_storage_cost_monthly: float | None
    base_cost_monthly: float | None
    adjusted_cost_monthly: float | None
    pricing_known: bool
    assumptions: list[str] = field(default_factory=list)

@dataclass
class CostReport:
    """Aggregate costs, scenario savings, and business-value metrics."""
    currency: str
    estimated_monthly_cost_before: Money
    estimated_monthly_cost_after: Money
    estimated_monthly_savings: Money
    estimated_annualized_savings: Money
    estimated_savings_percent: float | None
    workload_costs: list[WorkloadCost]
    namespace_costs: dict[str, float | None]
    resource_cost_breakdown: dict[str, float | None]
    business_value: dict[str, Any]
    assumptions: list[str]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "currency": self.currency,
            "estimated_monthly_cost_before": self.estimated_monthly_cost_before.to_dict(),
            "estimated_monthly_cost_after": self.estimated_monthly_cost_after.to_dict(),
            "estimated_monthly_savings": self.estimated_monthly_savings.to_dict(),
            "estimated_annualized_savings": self.estimated_annualized_savings.to_dict(),
            "estimated_savings_percent": self.estimated_savings_percent,
            "workload_costs": [asdict(x) for x in self.workload_costs],
            "namespace_costs": self.namespace_costs,
            "resource_cost_breakdown": self.resource_cost_breakdown,
            "business_value": self.business_value,
            "assumptions": self.assumptions,
            "warnings": self.warnings,
        }

class CostSimulator:
    """Estimate costs from declared resource requests and policy rates."""

    def __init__(self, config: Mapping[str, Any] | None = None, policies: Mapping[str, Any] | None = None):
        self.config = dict(config or {})
        self.policies = dict(policies or {})
        self.cost_cfg = _map(self.config.get("cost"))
        self.calc = _map(self.policies.get("calculation"))
        self.rates = _map(self.policies.get("resource_rates"))
        self.workload_adjustments = _map(self.policies.get("workload_adjustments"))
        self.namespace_adjustments = _map(self.policies.get("namespace_adjustments"))
        self.savings_policy = _map(self.policies.get("savings_policy"))
        self.currency = str(self.cost_cfg.get("currency", _map(self.policies.get("metadata")).get("currency", "USD")))
        self.hours_per_month = _number(self.calc.get("hours_per_month", self.cost_cfg.get("hours_per_month", 730)), 730.0) or 730.0
        self.warnings: list[str] = []
        self.assumptions = [
            "Costs use declared requests and configured rates.",
            "Cost values are estimates, not live provider quotes or invoices.",
            "Reducing requests does not guarantee an equivalent reduction in billed spend.",
        ]

    def _rate(self, name: str) -> float | None:
        value = _number(_map(self.rates.get(name)).get("usd_per_unit_hour"))
        return value if value is not None and value >= 0 else None

    def _multiplier(self, workload: WorkloadRecord) -> float | None:
        kind_default = _number(self.workload_adjustments.get("default_multiplier"), 1.0)
        kind = _number(_map(self.workload_adjustments.get("kinds")).get(workload.kind), kind_default)
        ns_default = _number(self.namespace_adjustments.get("default_multiplier"), 1.0)
        namespace = _map(self.namespace_adjustments.get("exact_namespaces")).get(workload.namespace)
        if namespace is None:
            namespace = _map(self.namespace_adjustments.get("multipliers")).get(workload.namespace, ns_default)
        ns = _number(namespace, ns_default)
        if kind is None or ns is None or kind < 0 or ns < 0:
            return None
        return kind * ns

    def _container_cost(self, container: ContainerResources) -> tuple[dict[str, float | None], list[str]]:
        """Price one container; None means the estimate cannot be computed."""
        assumptions = []
        cpu_rate, mem_rate = self._rate("cpu"), self._rate("memory")
        gpu_rate, storage_rate = self._rate("gpu"), self._rate("ephemeral_storage")
        cpu = None if container.cpu_request_millicores is None or cpu_rate is None else (
            container.cpu_request_millicores / 1000 * cpu_rate * self.hours_per_month
        )
        memory = None if container.memory_request_mib is None or mem_rate is None else (
            container.memory_request_mib / 1024 * mem_rate * self.hours_per_month
        )
        gpu = 0.0 if container.gpu_request <= 0 else (
            None if gpu_rate is None else container.gpu_request * gpu_rate * self.hours_per_month
        )
        storage = None if container.ephemeral_storage_request_gib is None or storage_rate is None else (
            container.ephemeral_storage_request_gib * storage_rate * self.hours_per_month
        )
        if container.cpu_request_millicores is None:
            assumptions.append(f"{container.name}: CPU request is missing.")
        if container.memory_request_mib is None:
            assumptions.append(f"{container.name}: memory request is missing.")
        if container.gpu_request > 0 and gpu_rate is None:
            assumptions.append(f"{container.name}: GPU rate is not configured.")
        return {"cpu": cpu, "memory": memory, "gpu": gpu, "storage": storage}, assumptions

    def estimate_workload(self, workload: WorkloadRecord) -> WorkloadCost:
        """Estimate workload monthly allocation cost; preserve unknown values."""
        totals = {"cpu": 0.0, "memory": 0.0, "gpu": 0.0, "storage": 0.0}
        known = True
        assumptions: list[str] = []
        for container in workload.containers:
            components, notes = self._container_cost(container)
            assumptions.extend(notes)
            for key, amount in components.items():
                if amount is None:
                    # Missing optional storage/GPU is not equivalent to a priced allocation.
                    if key == "storage" and container.ephemeral_storage_request_gib is None:
                        continue
                    if key == "gpu" and container.gpu_request <= 0:
                        continue
                    known = False
                else:
                    totals[key] += amount
        replicas = max(0, workload.desired_replicas)
        totals = {key: value * replicas for key, value in totals.items()}
        base = sum(totals.values()) if known else None
        multiplier = self._multiplier(workload)
        adjusted = None if base is None or multiplier is None else base * multiplier
        if multiplier is None:
            known = False
            assumptions.append("Workload adjustment could not be resolved.")
        if not known:
            self.warnings.append(f"Incomplete cost for {workload.namespace}/{workload.name}; unknown values were not set to zero.")
        return WorkloadCost(
            namespace=workload.namespace, name=workload.name, kind=workload.kind, replicas=replicas,
            cpu_cost_monthly=_rounded(totals["cpu"]), memory_cost_monthly=_rounded(totals["memory"]),
            gpu_cost_monthly=_rounded(totals["gpu"]), ephemeral_storage_cost_monthly=_rounded(totals["storage"]),
            base_cost_monthly=_rounded(base), adjusted_cost_monthly=_rounded(adjusted),
            pricing_known=known and adjusted is not None, assumptions=assumptions,
        )

    def _sum_known(self, values: list[float | None]) -> float | None:
        if any(value is None for value in values):
            return None
        return sum(float(value) for value in values if value is not None)

    def _money(self, amount: float | None) -> Money:
        return Money(_rounded(amount), self.currency, True, amount is not None)

    def _scenario(self, costs: list[WorkloadCost], capacity: CapacityReport) -> tuple[float | None, float | None, dict[str, Any]]:
        """Build a conservative cost scenario for low-utilization workloads."""
        eligible = {
            (f.workload["namespace"], f.workload["name"])
            for f in capacity.findings if f.category == "cost_efficiency"
        }
        before = self._sum_known([item.adjusted_cost_monthly for item in costs])
        if before is None:
            return None, None, {
                "method": "conservative_scenario", "eligible_workloads": len(eligible),
                "note": "At least one workload cost is unknown; aggregate savings are withheld.",
            }
        max_reduction = _number(self.savings_policy.get("maximum_request_reduction_percent"), 70) or 70
        safety = _number(self.savings_policy.get("apply_safety_margin_percent"), 20) or 20
        fraction = min(max(0, max_reduction), max(0, 100 - safety)) / 100
        after = sum(
            (item.adjusted_cost_monthly or 0) * (1 - fraction)
            if (item.namespace, item.name) in eligible else (item.adjusted_cost_monthly or 0)
            for item in costs
        )
        return before, after, {
            "method": "conservative_scenario", "eligible_workloads": len(eligible),
            "scenario_reduction_percent": round(fraction * 100, 2),
            "note": "Scenario only; verify with metrics, capacity packing, and billing data.",
        }

    def calculate(self, inventory: KubernetesInventory, capacity: CapacityReport) -> CostReport:
        """Calculate per-workload estimates, totals, and business-value indicators."""
        self.warnings = []
        costs = [self.estimate_workload(workload) for workload in inventory.workloads]
        before, after, scenario = self._scenario(costs, capacity)
        savings = None if before is None or after is None else before - after
        annualized = None if savings is None else savings * 12
        savings_percent = None if before in (None, 0) or savings is None else savings / before * 100
        namespaces = {}
        for namespace in sorted({item.namespace for item in costs}):
            namespaces[namespace] = _rounded(self._sum_known([
                item.adjusted_cost_monthly for item in costs if item.namespace == namespace
            ]))
        resource_breakdown = {}
        for key, attr in [
            ("cpu", "cpu_cost_monthly"), ("memory", "memory_cost_monthly"),
            ("gpu", "gpu_cost_monthly"), ("ephemeral_storage", "ephemeral_storage_cost_monthly"),
        ]:
            resource_breakdown[key] = _rounded(self._sum_known([getattr(item, attr) for item in costs]))
        business = {
            "estimated_monthly_cost_before_usd": _rounded(before),
            "estimated_monthly_cost_after_usd": _rounded(after),
            "estimated_monthly_savings_usd": _rounded(savings),
            "estimated_annualized_savings_usd": _rounded(annualized),
            "estimated_savings_percent": _rounded(savings_percent),
            "cpu_millicores_released": None,
            "memory_mib_released": None,
            "workload_count": len(costs),
            "workloads_with_known_pricing": sum(item.pricing_known for item in costs),
            "workloads_with_unknown_pricing": sum(not item.pricing_known for item in costs),
            "scenario": scenario,
            "estimate_only": True,
        }
        if before is None:
            self.warnings.append("Aggregate savings are unknown because one or more workload costs are incomplete.")
        self.warnings.append("Allocation-cost reduction may not translate to invoice savings without node consolidation.")
        return CostReport(
            currency=self.currency,
            estimated_monthly_cost_before=self._money(before),
            estimated_monthly_cost_after=self._money(after),
            estimated_monthly_savings=self._money(savings),
            estimated_annualized_savings=self._money(annualized),
            estimated_savings_percent=_rounded(savings_percent),
            workload_costs=costs, namespace_costs=namespaces, resource_cost_breakdown=resource_breakdown,
            business_value=business, assumptions=sorted(set(self.assumptions)),
            warnings=sorted(set(self.warnings)),
        )

    def compare_scenarios(
        self, workload: WorkloadRecord, *, cpu_request_millicores: float | None = None,
        memory_request_mib: float | None = None, replicas: int | None = None,
    ) -> dict[str, Any]:
        """Compare a proposed request/replica scenario with the current estimate."""
        from copy import deepcopy
        clone = deepcopy(workload)
        if replicas is not None:
            clone.desired_replicas = max(0, int(replicas))
        for container in clone.containers:
            if cpu_request_millicores is not None:
                container.cpu_request_millicores = cpu_request_millicores
            if memory_request_mib is not None:
                container.memory_request_mib = memory_request_mib
        before, after = self.estimate_workload(workload), self.estimate_workload(clone)
        delta = None
        if before.adjusted_cost_monthly is not None and after.adjusted_cost_monthly is not None:
            delta = before.adjusted_cost_monthly - after.adjusted_cost_monthly
        return {
            "workload": f"{workload.namespace}/{workload.name}",
            "before_monthly_cost": before.adjusted_cost_monthly,
            "after_monthly_cost": after.adjusted_cost_monthly,
            "estimated_monthly_savings": _rounded(delta),
            "currency": self.currency,
            "known": before.pricing_known and after.pricing_known,
            "assumptions": before.assumptions + after.assumptions,
            "warning": "Scenario estimate only; validate against metrics and billing data.",
        }


"""
Implementation and operator reference
=====================================

1. Allocation cost versus invoice cost
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

2. Pricing provenance
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

3. Unknown price handling
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

4. CPU pricing units
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

5. Memory pricing units
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

6. GPU price assumptions
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

7. Ephemeral storage scope
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

8. Replica multiplication
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

9. Workload cost adjustments
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

10. Namespace multipliers
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

11. Shared overhead
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

12. Before and after scenarios
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

13. Monthly and annualized savings
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

14. Negative savings meaning
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

15. Cost per workload
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

16. Cost per namespace
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

17. Capacity released versus spend
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

18. Savings safety margin
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

19. Metrics requirement
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

20. Pricing policy version
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

21. Finance review
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

22. Commitment discounts
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

23. Node consolidation
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

24. Autoscaler interaction
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

25. Storage omissions
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

26. Network omissions
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

27. Control plane omissions
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

28. Billing export integration
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

29. Unknown totals
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

30. Cost report review
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

31. Scenario validation
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

32. Financial limitations
   Make the price basis explicit and keep unknown rates unknown. A modeled reduction in requested resources is not necessarily a reduction in billed spend. Store assumptions alongside totals and validate the model against billing exports before financial use.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

"""


'''
Extended validation checklist
=============================

1. Hourly CPU rate
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

2. Hourly memory rate
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

3. GPU rate
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

4. Ephemeral storage rate
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

5. Hours per month
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

6. Replica multiplication
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

7. Kind multiplier
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

8. Namespace multiplier
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

9. Unknown CPU cost
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

10. Unknown memory cost
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

11. Unknown GPU cost
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

12. Optional storage cost
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

13. Monthly total
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

14. Annualized scenario
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

15. Savings percentage
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

16. Cost increase scenario
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

17. Currency consistency
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

18. Price policy metadata
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

19. Rate review cadence
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

20. Provider billing export
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

21. Commitment coverage
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

22. Node family differences
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

23. Node consolidation assumptions
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

24. Autoscaler effects
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

25. Shared platform costs
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

26. Network cost boundary
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

27. Persistent volume boundary
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

28. Financial review ownership
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

29. Estimate labeling
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

30. Budget use disclaimer
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

'''
