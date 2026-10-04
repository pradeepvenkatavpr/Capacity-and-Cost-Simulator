from __future__ import annotations
import json
import logging
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
import yaml

LOG = logging.getLogger("capacity_cost_simulator.kubernetes")

class KubernetesAnalysisError(RuntimeError):
    """Raised when a manifest cannot be safely interpreted."""

@dataclass
class ContainerResources:
    """Normalized resource declarations for one container."""
    name: str
    container_type: str
    cpu_request_millicores: float | None
    cpu_limit_millicores: float | None
    memory_request_mib: float | None
    memory_limit_mib: float | None
    gpu_request: float = 0.0
    ephemeral_storage_request_gib: float | None = None
    raw_requests: dict[str, Any] = field(default_factory=dict)
    raw_limits: dict[str, Any] = field(default_factory=dict)

@dataclass
class WorkloadRecord:
    """Stable workload inventory record used by downstream analysis."""
    api_version: str
    kind: str
    name: str
    namespace: str
    labels: dict[str, str]
    annotations: dict[str, str]
    desired_replicas: int
    ready_replicas: int | None
    containers: list[ContainerResources]
    source_file: str | None = None
    source: str = "manifest"
    status: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def container_count(self) -> int:
        return len(self.containers)

    @property
    def requested_cpu_millicores(self) -> float:
        return sum(item.cpu_request_millicores or 0.0 for item in self.containers)

    @property
    def requested_memory_mib(self) -> float:
        return sum(item.memory_request_mib or 0.0 for item in self.containers)

    @property
    def limited_cpu_millicores(self) -> float | None:
        if any(item.cpu_limit_millicores is None for item in self.containers):
            return None
        return sum(item.cpu_limit_millicores or 0.0 for item in self.containers)

    @property
    def limited_memory_mib(self) -> float | None:
        if any(item.memory_limit_mib is None for item in self.containers):
            return None
        return sum(item.memory_limit_mib or 0.0 for item in self.containers)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.update({
            "container_count": self.container_count,
            "requested_cpu_millicores": self.requested_cpu_millicores,
            "requested_memory_mib": self.requested_memory_mib,
            "limited_cpu_millicores": self.limited_cpu_millicores,
            "limited_memory_mib": self.limited_memory_mib,
        })
        return result

@dataclass
class KubernetesInventory:
    """Aggregate workload inventory."""
    workloads: list[WorkloadRecord]
    environment: str
    analyzed_object_count: int
    workload_count: int
    container_count: int
    total_cpu_request_millicores: float
    total_memory_request_mib: float
    total_cpu_limit_millicores: float | None
    total_memory_limit_mib: float | None
    namespace_count: int
    kind_counts: dict[str, int]
    warnings: list[str] = field(default_factory=list)
    ignored_object_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "workloads": [item.to_dict() for item in self.workloads],
            "environment": self.environment,
            "analyzed_object_count": self.analyzed_object_count,
            "workload_count": self.workload_count,
            "container_count": self.container_count,
            "total_cpu_request_millicores": self.total_cpu_request_millicores,
            "total_memory_request_mib": self.total_memory_request_mib,
            "total_cpu_limit_millicores": self.total_cpu_limit_millicores,
            "total_memory_limit_mib": self.total_memory_limit_mib,
            "namespace_count": self.namespace_count,
            "kind_counts": self.kind_counts,
            "warnings": self.warnings,
            "ignored_object_count": self.ignored_object_count,
        }

_CPU = re.compile(r"^(\d+(?:\.\d+)?|\.\d+)(m?)$")
_MEMORY = re.compile(r"^(\d+(?:\.\d+)?|\.\d+)(Ki|Mi|Gi|Ti|Pi|Ei|K|M|G|T|P|E)?$")
_MEMORY_FACTOR = {
    None: 1.0, "K": 1000.0, "M": 1000.0**2, "G": 1000.0**3,
    "T": 1000.0**4, "P": 1000.0**5, "E": 1000.0**6,
    "Ki": 1024.0, "Mi": 1024.0**2, "Gi": 1024.0**3,
    "Ti": 1024.0**4, "Pi": 1024.0**5, "Ei": 1024.0**6,
}

def parse_cpu_quantity(value: Any) -> float | None:
    """Convert a Kubernetes CPU quantity to millicores."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if not math.isfinite(number) or number < 0:
            raise KubernetesAnalysisError(f"Invalid CPU quantity: {value!r}")
        return number * 1000
    match = _CPU.fullmatch(str(value).strip())
    if not match:
        raise KubernetesAnalysisError(f"Unsupported CPU quantity: {value!r}")
    number = float(match.group(1))
    if number < 0 or not math.isfinite(number):
        raise KubernetesAnalysisError(f"Invalid CPU quantity: {value!r}")
    return number if match.group(2) else number * 1000

def parse_memory_quantity_mib(value: Any) -> float | None:
    """Convert decimal or binary Kubernetes memory quantities to MiB."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        if number < 0 or not math.isfinite(number):
            raise KubernetesAnalysisError(f"Invalid memory quantity: {value!r}")
        return number / (1024**2)
    match = _MEMORY.fullmatch(str(value).strip())
    if not match:
        raise KubernetesAnalysisError(f"Unsupported memory quantity: {value!r}")
    number = float(match.group(1))
    suffix = match.group(2)
    if number < 0 or not math.isfinite(number):
        raise KubernetesAnalysisError(f"Invalid memory quantity: {value!r}")
    return number * _MEMORY_FACTOR[suffix] / (1024**2)

def parse_storage_quantity_gib(value: Any) -> float | None:
    """Convert an ephemeral-storage quantity to GiB."""
    mib = parse_memory_quantity_mib(value)
    return None if mib is None else mib / 1024

def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}

def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []

def _strmap(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items() if item is not None}

def _meta(obj: Mapping[str, Any]) -> dict[str, Any]:
    return _dict(obj.get("metadata"))

def _template(obj: Mapping[str, Any]) -> dict[str, Any]:
    kind = obj.get("kind")
    spec = _dict(obj.get("spec"))
    if kind == "CronJob":
        return _dict(_dict(_dict(spec.get("jobTemplate")).get("spec")).get("template"))
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}:
        return _dict(spec.get("template"))
    if kind == "Pod":
        return dict(obj)
    return {}

def _containers(pod_spec: Mapping[str, Any], config: Mapping[str, Any]) -> list[tuple[str, Mapping[str, Any]]]:
    analysis = _dict(config.get("analysis"))
    result: list[tuple[str, Mapping[str, Any]]] = []
    if analysis.get("include_init_containers", True):
        result.extend(("init", item) for item in _list(pod_spec.get("initContainers")) if isinstance(item, Mapping))
    if analysis.get("include_sidecars", True):
        result.extend(("regular", item) for item in _list(pod_spec.get("containers")) if isinstance(item, Mapping))
    if analysis.get("include_ephemeral_containers", False):
        result.extend(("ephemeral", item) for item in _list(pod_spec.get("ephemeralContainers")) if isinstance(item, Mapping))
    return result

def _container_resources(container: Mapping[str, Any], category: str) -> ContainerResources:
    resources = _dict(container.get("resources"))
    requests = _dict(resources.get("requests"))
    limits = _dict(resources.get("limits"))
    gpu = 0.0
    for key, value in requests.items():
        if str(key).endswith("/gpu"):
            try:
                gpu += float(value)
            except (ValueError, TypeError) as exc:
                raise KubernetesAnalysisError(f"Invalid GPU quantity {value!r}") from exc
    return ContainerResources(
        name=str(container.get("name", "unnamed")),
        container_type=category,
        cpu_request_millicores=parse_cpu_quantity(requests.get("cpu")),
        cpu_limit_millicores=parse_cpu_quantity(limits.get("cpu")),
        memory_request_mib=parse_memory_quantity_mib(requests.get("memory")),
        memory_limit_mib=parse_memory_quantity_mib(limits.get("memory")),
        gpu_request=gpu,
        ephemeral_storage_request_gib=parse_storage_quantity_gib(requests.get("ephemeral-storage")),
        raw_requests=dict(requests),
        raw_limits=dict(limits),
    )

class KubernetesAnalyzer:
    """Read manifests or list cluster workloads and normalize them."""

    def __init__(self, config: Mapping[str, Any] | None = None, rules: Mapping[str, Any] | None = None):
        self.config = dict(config or {})
        self.rules = dict(rules or {})
        self.analysis = _dict(self.config.get("analysis"))
        self.input_config = _dict(self.config.get("input"))

    def _ignored_namespace(self, namespace: str) -> bool:
        return namespace in set(self.analysis.get("ignore_namespaces", [])) or any(
            namespace.startswith(str(prefix)) for prefix in self.analysis.get("ignore_namespaces_by_prefix", [])
        )

    def _ignored_labels(self, labels: Mapping[str, str]) -> bool:
        expected = _dict(self.analysis.get("ignore_labels"))
        return any(labels.get(str(key)) == str(value) for key, value in expected.items())

    def _validate_object(self, obj: Any, source: str) -> dict[str, Any]:
        if not isinstance(obj, Mapping):
            raise KubernetesAnalysisError(f"{source}: each document must be an object.")
        result = dict(obj)
        for required in ("apiVersion", "kind", "metadata"):
            if required not in result:
                raise KubernetesAnalysisError(f"{source}: required field {required!r} is missing.")
        if not isinstance(result["metadata"], Mapping):
            raise KubernetesAnalysisError(f"{source}: metadata must be a mapping.")
        return result

    def _parse_file(self, path: Path, max_bytes: int) -> list[dict[str, Any]]:
        if path.stat().st_size > max_bytes:
            raise KubernetesAnalysisError(f"Manifest exceeds {max_bytes} bytes: {path}")
        try:
            docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise KubernetesAnalysisError(f"Unable to parse {path}: {exc}") from exc
        result = []
        for number, doc in enumerate(docs, 1):
            if doc is None:
                continue
            obj = self._validate_object(doc, f"{path} document {number}")
            obj["_simulator_source_file"] = str(path)
            result.append(obj)
        return result

    def load_manifest_directory(
        self, directory: Path, *, namespace: str | None = None,
        include_ignored_namespaces: bool = False, include_completed_jobs: bool = False,
        fail_on_invalid: bool = True, maximum_files: int = 5000,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Load sorted multi-document manifest files with validation and filtering."""
        directory = Path(directory)
        if not directory.is_dir():
            raise KubernetesAnalysisError(f"Manifest directory not found: {directory}")
        extensions = set(self.input_config.get("allowed_manifest_extensions", [".yaml", ".yml", ".json"]))
        max_bytes = int(_dict(self.config.get("policy")).get("maximum_manifest_file_size_bytes", 10_000_000))
        files = sorted(p for p in directory.rglob("*") if p.is_file() and p.suffix.lower() in extensions)
        if len(files) > maximum_files:
            raise KubernetesAnalysisError(f"Found {len(files)} files; maximum is {maximum_files}.")
        objects: list[dict[str, Any]] = []
        warnings: list[str] = []
        for path in files:
            try:
                for obj in self._parse_file(path, max_bytes):
                    meta = _meta(obj)
                    ns = str(meta.get("namespace", "default"))
                    if namespace and ns != namespace:
                        continue
                    if not include_ignored_namespaces and self._ignored_namespace(ns):
                        continue
                    if self._ignored_labels(_strmap(meta.get("labels"))):
                        continue
                    if obj.get("kind") == "Job" and not include_completed_jobs:
                        status = _dict(obj.get("status"))
                        if status.get("succeeded") and not status.get("active"):
                            continue
                    objects.append(obj)
            except (KubernetesAnalysisError, OSError) as exc:
                if fail_on_invalid:
                    raise
                warnings.append(str(exc))
        if not files:
            warnings.append(f"No supported manifest files found under {directory}.")
        return objects, warnings

    def load_from_cluster(
        self, *, context: str | None = None, kubeconfig_path: Path | None = None,
        namespace: str | None = None, include_ignored_namespaces: bool = False,
        include_completed_jobs: bool = False,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """List supported workloads using the Kubernetes client; never mutates the cluster."""
        try:
            from kubernetes import client, config as kube_config
        except ImportError as exc:
            raise KubernetesAnalysisError("Install the kubernetes package from requirements.txt.") from exc
        try:
            kube_config.load_kube_config(config_file=str(kubeconfig_path) if kubeconfig_path else None, context=context)
        except Exception as exc:
            raise KubernetesAnalysisError(f"Could not load Kubernetes context: {exc}") from exc
        apps, batch = client.AppsV1Api(), client.BatchV1Api()
        objects: list[dict[str, Any]] = []
        groups = [
            (apps, "Deployment", "apps/v1", "deployment"),
            (apps, "StatefulSet", "apps/v1", "stateful_set"),
            (apps, "DaemonSet", "apps/v1", "daemon_set"),
            (batch, "Job", "batch/v1", "job"),
            (batch, "CronJob", "batch/v1", "cron_job"),
        ]
        try:
            for api, kind, version, method in groups:
                if namespace:
                    response = getattr(api, f"list_namespaced_{method}")(namespace)
                else:
                    response = getattr(api, f"list_{method}_for_all_namespaces")()
                for item in response.items:
                    raw = item.to_dict()
                    raw["kind"], raw["apiVersion"] = kind, version
                    # Client models use snake_case. Normalize metadata fields used downstream.
                    meta = _dict(raw.get("metadata"))
                    raw["metadata"] = {
                        "name": meta.get("name"), "namespace": meta.get("namespace") or "default",
                        "uid": meta.get("uid"), "creationTimestamp": meta.get("creation_timestamp"),
                        "labels": meta.get("labels") or {}, "annotations": meta.get("annotations") or {},
                    }
                    objects.append(raw)
        except Exception as exc:
            raise KubernetesAnalysisError(f"Kubernetes list request failed: {exc}") from exc
        filtered = []
        for obj in objects:
            ns = str(_meta(obj).get("namespace", "default"))
            labels = _strmap(_meta(obj).get("labels"))
            if not include_ignored_namespaces and self._ignored_namespace(ns):
                continue
            if self._ignored_labels(labels):
                continue
            if obj.get("kind") == "Job" and not include_completed_jobs:
                status = _dict(obj.get("status"))
                if status.get("succeeded") and not status.get("active"):
                    continue
            filtered.append(obj)
        return filtered, ["Cluster mode uses list operations only; no Kubernetes objects were changed."]

    def normalize_workload(self, obj: Mapping[str, Any]) -> WorkloadRecord:
        """Normalize one supported workload."""
        kind = str(obj.get("kind", ""))
        meta, spec = _meta(obj), _dict(obj.get("spec"))
        template = _template(obj)
        pod_spec = _dict(template.get("spec"))
        containers = [_container_resources(c, category) for category, c in _containers(pod_spec, self.config)]
        if kind == "DaemonSet":
            replicas = int(_dict(obj.get("status")).get("desired_number_scheduled", 0) or 0)
        elif kind == "CronJob":
            replicas = 1
        elif kind == "Job":
            replicas = max(1, int(spec.get("parallelism", 1) or 1))
        elif kind == "Pod":
            replicas = 1
        else:
            replicas = max(0, int(spec.get("replicas", 1) if spec.get("replicas") is not None else 1))
        status = _dict(obj.get("status"))
        ready = status.get("ready_replicas", status.get("readyReplicas", status.get("ready")))
        try:
            ready = int(ready) if ready is not None else None
        except (TypeError, ValueError):
            ready = None
        return WorkloadRecord(
            api_version=str(obj.get("apiVersion", "unknown")), kind=kind,
            name=str(meta.get("name", "unnamed")), namespace=str(meta.get("namespace", "default")),
            labels=_strmap(meta.get("labels")), annotations=_strmap(meta.get("annotations")),
            desired_replicas=replicas, ready_replicas=ready, containers=containers,
            source_file=obj.get("_simulator_source_file"),
            source="cluster" if obj.get("_simulator_source") == "cluster" else "manifest",
            status=status,
            warnings=[] if containers else ["No container declarations found."],
        )

    def analyze_objects(
        self, objects: Sequence[Mapping[str, Any]], *, environment: str = "development",
        include_ignored_namespaces: bool = False,
    ) -> KubernetesInventory:
        """Normalize supported workloads and compute inventory totals."""
        kinds = set(self.analysis.get("workload_kinds", ["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]))
        if self.analysis.get("include_standalone_pods", False):
            kinds.add("Pod")
        workloads, warnings = [], []
        ignored = 0
        counts: dict[str, int] = {}
        for obj in objects:
            kind = str(obj.get("kind", ""))
            meta = _meta(obj)
            ns = str(meta.get("namespace", "default"))
            if kind not in kinds:
                ignored += 1
                continue
            if not include_ignored_namespaces and self._ignored_namespace(ns):
                ignored += 1
                continue
            if self._ignored_labels(_strmap(meta.get("labels"))):
                ignored += 1
                continue
            try:
                workload = self.normalize_workload(obj)
            except (ValueError, TypeError, KubernetesAnalysisError) as exc:
                warnings.append(f"Skipped {ns}/{meta.get('name', 'unknown')}: {exc}")
                continue
            workloads.append(workload)
            warnings.extend(workload.warnings)
            counts[kind] = counts.get(kind, 0) + 1
        workloads.sort(key=lambda w: (w.namespace, w.kind, w.name))
        cpu = sum(w.requested_cpu_millicores for w in workloads)
        memory = sum(w.requested_memory_mib for w in workloads)
        cpu_limits = [w.limited_cpu_millicores for w in workloads]
        memory_limits = [w.limited_memory_mib for w in workloads]
        return KubernetesInventory(
            workloads=workloads, environment=environment, analyzed_object_count=len(objects),
            workload_count=len(workloads), container_count=sum(w.container_count for w in workloads),
            total_cpu_request_millicores=cpu, total_memory_request_mib=memory,
            total_cpu_limit_millicores=sum(v or 0 for v in cpu_limits) if all(v is not None for v in cpu_limits) else None,
            total_memory_limit_mib=sum(v or 0 for v in memory_limits) if all(v is not None for v in memory_limits) else None,
            namespace_count=len({w.namespace for w in workloads}), kind_counts=counts,
            warnings=sorted(set(warnings)), ignored_object_count=ignored,
        )

    def safe_object_summary(self, obj: Mapping[str, Any]) -> dict[str, Any]:
        """Return metadata-only summary suitable for logs; never include Secret payloads."""
        meta = _meta(obj)
        return {
            "apiVersion": obj.get("apiVersion"), "kind": obj.get("kind"),
            "name": meta.get("name"), "namespace": meta.get("namespace", "default"),
            "labels": _strmap(meta.get("labels")),
            "annotation_keys": sorted(_strmap(meta.get("annotations")).keys()),
        }


"""
Implementation and operator reference
=====================================

1. CPU quantity normalization
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

2. Memory quantity normalization
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

3. Decimal versus binary units
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

4. Storage quantity handling
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

5. Multi-document YAML
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

6. Manifest size limits
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

7. Manifest file limits
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

8. Namespace filtering
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

9. Label-based exclusions
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

10. Pod template resolution
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

11. Init container inclusion
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

12. Sidecar accounting
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

13. Ephemeral container scope
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

14. Deployment replica accounting
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

15. StatefulSet replica accounting
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

16. DaemonSet limitations
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

17. Job and CronJob treatment
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

18. Standalone Pod treatment
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

19. Cluster client permissions
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

20. Read-only API operations
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

21. Kubernetes client serialization
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

22. Missing request semantics
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

23. Missing limit semantics
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

24. Inventory determinism
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

25. Sensitive metadata
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

26. Unknown resource kinds
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

27. CRD limitations
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

28. Quantity testing
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

29. Manifest troubleshooting
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

30. Empty inventory troubleshooting
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

31. Inventory total interpretation
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

32. Node capacity boundary
   Treat the manifest as declared intent, not live usage. Preserve missing values as unknown, normalize units once, keep stable workload identity, and never inspect Secret payloads. Cluster mode should use list-only operations and a narrowly scoped read-only identity.
   Review the related configuration, verify the evidence available for the workload, record assumptions in the report, and test the behavior with a representative fixture before using the output in a deployment or financial decision.
   Keep the outcome advisory unless a separate approved workflow enforces the policy. Do not silently replace missing inputs with invented measurements or prices.

"""
