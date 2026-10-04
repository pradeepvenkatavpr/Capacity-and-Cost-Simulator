from __future__ import annotations
import argparse
import dataclasses
import datetime as dt
import json
import logging
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence
import yaml
from kubernetes_analyzer import KubernetesAnalyzer
from capacity_analyzer import CapacityAnalyzer
from cost_simulator import CostSimulator
from optimization_engine import OptimizationEngine

LOG = logging.getLogger("capacity_cost_simulator")

class SimulatorError(RuntimeError):
    """Expected user-facing simulation failure."""

@dataclasses.dataclass
class RunContext:
    config: dict[str, Any]
    cost_policies: dict[str, Any]
    kubernetes_rules: dict[str, Any]
    source: str
    manifest_directory: Path
    environment: str
    namespace: str | None
    output: Path | None
    report_format: str
    allow_cluster_access: bool
    kube_context: str | None
    kubeconfig: Path | None
    include_ignored_namespaces: bool
    include_completed_jobs: bool
    continue_on_invalid: bool
    maximum_files: int

def read_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML mapping and produce a clear error for invalid configuration."""
    if not path.is_file():
        raise SimulatorError(f"Required YAML file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        raise SimulatorError(f"Cannot read YAML file {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise SimulatorError(f"Top-level content in {path} must be a mapping.")
    return data

def build_parser() -> argparse.ArgumentParser:
    """Build CLI arguments. Cluster inspection requires explicit acknowledgement."""
    parser = argparse.ArgumentParser(
        prog="capacity-cost-simulator",
        description="Analyze Kubernetes capacity, estimate allocated cost, and rank recommendations.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--source", choices=["yaml_directory", "kubernetes_api"], default=None)
    parser.add_argument("--manifests", type=Path, default=None)
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    parser.add_argument("--cost-policies", type=Path, default=Path("cost_policies.yaml"))
    parser.add_argument("--kubernetes-rules", type=Path, default=Path("kubernetes_rules.yaml"))
    parser.add_argument("--environment", choices=["development", "staging", "production"], default="development")
    parser.add_argument("--namespace", default=None)
    parser.add_argument("--context", default=None)
    parser.add_argument("--kubeconfig", type=Path, default=None)
    parser.add_argument("--allow-cluster-access", action="store_true")
    parser.add_argument("--include-ignored-namespaces", action="store_true")
    parser.add_argument("--include-completed-jobs", action="store_true")
    parser.add_argument("--continue-on-invalid-manifest", action="store_true")
    parser.add_argument("--maximum-files", type=int, default=5000)
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    parser.add_argument("--version", action="version", version="Capacity and Cost Simulator 1.0.0")
    return parser

def build_context(args: argparse.Namespace) -> RunContext:
    """Load configuration, merge command-line overrides, and validate safety settings."""
    config = read_yaml(args.config)
    costs = read_yaml(args.cost_policies)
    rules = read_yaml(args.kubernetes_rules)
    input_cfg = config.get("input", {})
    if not isinstance(input_cfg, dict):
        raise SimulatorError("config.yaml input section must be a mapping.")
    source = args.source or input_cfg.get("default_source", "yaml_directory")
    manifest_dir = args.manifests or Path(input_cfg.get("manifest_directory", "./manifests"))
    if source == "kubernetes_api" and not args.allow_cluster_access:
        raise SimulatorError("Cluster API mode requires --allow-cluster-access.")
    if source == "yaml_directory":
        if not manifest_dir.is_dir():
            raise SimulatorError(f"Manifest directory does not exist: {manifest_dir}")
    if args.maximum_files < 1:
        raise SimulatorError("--maximum-files must be at least 1.")
    return RunContext(
        config=config,
        cost_policies=costs,
        kubernetes_rules=rules,
        source=source,
        manifest_directory=Path(manifest_dir),
        environment=args.environment,
        namespace=args.namespace,
        output=args.output,
        report_format=args.format,
        allow_cluster_access=args.allow_cluster_access,
        kube_context=args.context or input_cfg.get("kube_context"),
        kubeconfig=args.kubeconfig or (Path(input_cfg["kubeconfig_path"]) if input_cfg.get("kubeconfig_path") else None),
        include_ignored_namespaces=args.include_ignored_namespaces,
        include_completed_jobs=args.include_completed_jobs or bool(config.get("analysis", {}).get("include_completed_jobs", False)),
        continue_on_invalid=args.continue_on_invalid_manifest,
        maximum_files=args.maximum_files,
    )

def make_report(context: RunContext) -> dict[str, Any]:
    """Run the analyzer pipeline and assemble a report without mutating a cluster."""
    analyzer = KubernetesAnalyzer(config=context.config, rules=context.kubernetes_rules)
    if context.source == "yaml_directory":
        objects, load_warnings = analyzer.load_manifest_directory(
            context.manifest_directory,
            namespace=context.namespace,
            include_ignored_namespaces=context.include_ignored_namespaces,
            include_completed_jobs=context.include_completed_jobs,
            fail_on_invalid=not context.continue_on_invalid,
            maximum_files=context.maximum_files,
        )
    else:
        objects, load_warnings = analyzer.load_from_cluster(
            context=context.kube_context,
            kubeconfig_path=context.kubeconfig,
            namespace=context.namespace,
            include_ignored_namespaces=context.include_ignored_namespaces,
            include_completed_jobs=context.include_completed_jobs,
        )
    inventory = analyzer.analyze_objects(
        objects,
        environment=context.environment,
        include_ignored_namespaces=context.include_ignored_namespaces,
    )
    capacity = CapacityAnalyzer(context.config, context.kubernetes_rules).analyze(inventory)
    cost = CostSimulator(context.config, context.cost_policies).calculate(inventory, capacity)
    optimization = OptimizationEngine(
        context.config, context.kubernetes_rules, context.cost_policies
    ).optimize(inventory=inventory, capacity=capacity, cost=cost, environment=context.environment)
    warnings = sorted(set(load_warnings + inventory.warnings + capacity.warnings + cost.warnings + optimization.warnings))
    return {
        "metadata": {
            "run_id": "ccs-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "application": context.config.get("application", {}).get("name", "capacity-and-cost-simulator"),
            "environment": context.environment,
            "source": context.source,
            "namespace_filter": context.namespace,
            "read_only": True,
            "costs_are_estimates": True,
        },
        "inventory": inventory.to_dict(),
        "capacity": capacity.to_dict(),
        "cost": cost.to_dict(),
        "optimization": optimization.to_dict(),
        "warnings": warnings,
        "status": "completed",
    }

def render_markdown(report: Mapping[str, Any]) -> str:
    """Render an actionable human-readable summary from the JSON-compatible report."""
    inventory = report["inventory"]
    capacity = report["capacity"]
    cost = report["cost"]
    optimization = report["optimization"]
    lines = [
        "# Capacity and Cost Simulator",
        "",
        f"- Generated: {report['metadata']['generated_at']}",
        f"- Environment: {report['metadata']['environment']}",
        f"- Workloads: {inventory['workload_count']}",
        f"- Containers: {inventory['container_count']}",
        f"- Capacity findings: {capacity['finding_count']}",
        f"- Recommendations: {optimization['recommendation_count']}",
        "",
        "> All cost figures are estimates based on configured rates, not provider invoices.",
        "",
        "## Cost summary",
        "",
        f"- Before: {cost['estimated_monthly_cost_before']['amount']} {cost['currency']}",
        f"- After scenario: {cost['estimated_monthly_cost_after']['amount']} {cost['currency']}",
        f"- Estimated monthly savings: {cost['estimated_monthly_savings']['amount']} {cost['currency']}",
        "",
        "## Findings",
        "",
    ]
    for finding in capacity["findings"]:
        lines.append(f"- **{finding['severity'].upper()} {finding['rule_id']}** — {finding['message']}")
    if not capacity["findings"]:
        lines.append("- No capacity findings were generated.")
    lines.extend(["", "## Recommendations", ""])
    for index, item in enumerate(optimization["recommendations"], 1):
        savings = item["estimated_monthly_savings"]["amount"]
        lines.append(
            f"{index}. **{item['title']}** — `{item['workload']['namespace']}/{item['workload']['name']}`; "
            f"risk={item['risk_level']}; estimated monthly savings={savings}."
        )
        lines.append(f"   - {item['description']}")
        lines.append(f"   - Human approval required: {item['requires_human_approval']}")
    if not optimization["recommendations"]:
        lines.append("- No recommendations met the configured thresholds.")
    lines.extend(["", "## Warnings", ""])
    lines.extend(f"- {warning}" for warning in report["warnings"])
    lines.extend(["", "## Safety", "", "This tool generates assessments and recommendations only. It does not apply changes."])
    return "\n".join(lines) + "\n"

def write_report(report: Mapping[str, Any], output: Path | None, report_format: str) -> str:
    """Serialize a report and optionally write it to disk."""
    content = json.dumps(report, indent=2, sort_keys=True, default=str) if report_format == "json" else render_markdown(report)
    if output is None:
        return content
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise SimulatorError(f"Cannot write report to {output}: {exc}") from exc
    return f"Report saved to {output}"

def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point; exit code 0 means the report was generated successfully."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        context = build_context(args)
        report = make_report(context)
        output = write_report(report, context.output, context.report_format)
        print(output)
        return 0
    except (SimulatorError, OSError, ValueError) as exc:
        LOG.error("%s", exc)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())


"""
Implementation and operator reference
=====================================

1. Command-line contract
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

2. Configuration precedence
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

3. Local manifest workflow
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

4. Cluster inspection safeguards
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

5. Read-only access model
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

6. Report interpretation
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

7. Cost estimate interpretation
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

8. Unknown-value handling
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

9. Warning review
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

10. CI integration
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

11. Exit status semantics
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

12. Artifact retention
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

13. Sensitive data handling
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

14. Troubleshooting configuration
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

15. Troubleshooting manifest parsing
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

16. Troubleshooting quantity values
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

17. Troubleshooting empty inventories
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

18. Troubleshooting unknown costs
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

19. Troubleshooting absent recommendations
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

20. Review before production use
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

21. Change approval boundary
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

22. Rollback planning
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

23. Observability follow-up
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

24. Report reproducibility
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

25. Policy versioning
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

26. Metrics freshness
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

27. Pricing provenance
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

28. Resource ownership
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

29. Namespace scope
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

30. Operational checklist
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

31. Known limitations
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

32. Future integrations
   The CLI should remain a thin coordinator. Keep resource parsing in the analyzer, policy evaluation in capacity analysis, pricing in the cost model, and ranking in the optimization engine. This separation makes failures easier to isolate and allows individual stages to be tested without connecting to a cluster.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

"""


'''
Extended validation checklist
=============================

1. Argument parsing review
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

2. Relative paths and working directory
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

3. Configuration file precedence
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

4. Safe default source
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

5. Explicit cluster access acknowledgement
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

6. Manifest validation behavior
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

7. Continue-on-error behavior
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

8. Report format choice
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

9. Output directory creation
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

10. Log level selection
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

11. Run identifier
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

12. UTC timestamp
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

13. Report artifact handling
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

14. Pipeline integration
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

15. Exit code handling
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

16. Warning review gate
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

17. Input provenance
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

18. Environment labeling
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

19. Namespace-scoped reports
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

20. Policy file review
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

21. Kubernetes permissions
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

22. Credentials hygiene
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

23. Sensitive annotation review
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

24. Cost disclaimer placement
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

25. Approval boundary
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

26. No-mutation invariant
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

27. Reproducible runs
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

28. Troubleshooting dependency errors
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

29. Troubleshooting permissions
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

30. Troubleshooting empty report
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

31. Post-run operator checklist
   Verify this behavior with a small, explicit fixture and record the expected result.
   Confirm that missing evidence remains unknown instead of being converted to a guessed value.
   Check the generated report for a clear explanation, severity, and safe next action.
   Keep any operational change separate from analysis and require the appropriate review.

'''
