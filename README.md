# ☸️ Capacity and Cost Simulator — Kubernetes Optimization + Measurable Business Value

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Workload_Analysis-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)
![PyYAML](https://img.shields.io/badge/PyYAML-Configuration-CB171E?style=for-the-badge&logo=yaml&logoColor=white)
![Cost](https://img.shields.io/badge/Cost-Simulation-2E8B57?style=for-the-badge)
![Optimization](https://img.shields.io/badge/Optimization-Decision_Support-orange?style=for-the-badge)
![Safety](https://img.shields.io/badge/Mode-Analyze_And_Recommend-008CBA?style=for-the-badge)

---

# 👨‍💻 Developed By

### Pradeep

---

# 📂 Repository Name

### `capacity-and-cost-simulator`

---

# 🚀 About This Project

Capacity and Cost Simulator is a Python-based Kubernetes optimization and financial decision-support project. It analyzes Kubernetes workload manifests or, when explicitly enabled, reads workload information from a Kubernetes cluster. It evaluates resource configuration and capacity signals, estimates resource costs using configurable pricing policies, and produces prioritized optimization recommendations with potential business value.

Kubernetes teams need to balance reliability, performance, capacity, and cloud spending. CPU and memory requests that are consistently larger than workload needs can contribute to inefficient capacity usage. Requests that are too small can create scheduling pressure or performance risk. Replica counts, resource limits, workload criticality, and incomplete utilization evidence also affect whether an optimization is appropriate.

This project brings those considerations into one assessment workflow:

- Kubernetes workload and resource inventory.
- Configurable capacity and policy checks.
- Estimated CPU, memory, GPU, and optional storage cost calculations where supported by the pricing policy.
- Before-and-after scenario comparison for supported recommendations.
- Optimization scoring and prioritization.
- JSON or Markdown reporting for engineering and business review.

The tool is intended for analysis and recommendation. It does **not** automatically patch Kubernetes resources, scale workloads, delete resources, or apply optimization recommendations. Cost estimates are only as reliable as the configured rates, workload inventory, metrics, and assumptions supplied to the simulator.

---

# ❗ Problem Statement

Kubernetes teams often have to answer technical and financial questions at the same time:

- Which workloads have missing or inconsistent CPU and memory requests or limits?
- Which workloads may be over-provisioned or under-provisioned?
- Which changes could reduce estimated monthly infrastructure cost?
- What operational risks could result from reducing resource allocations or replicas?
- Which recommendations have the strongest combination of savings, confidence, and implementation priority?
- How can engineers explain potential savings to platform owners and business stakeholders?
- How can teams compare options without automatically modifying a running cluster?

Capacity and Cost Simulator addresses these questions by combining workload analysis, configurable rules, cost simulation, and optimization recommendations in a single reporting workflow.

---

# 🎯 System Objectives

- Inventory Kubernetes workloads from YAML manifests or an explicitly authorized cluster read.
- Normalize resource quantities to a consistent representation for comparison.
- Inspect workload resource requests, limits, replica settings, and supported capacity signals.
- Evaluate configured Kubernetes rules and produce explainable findings.
- Estimate costs using rates defined in `cost_policies.yaml`.
- Compare baseline and proposed resource scenarios when the necessary inputs and supported rules are available.
- Rank optimization opportunities using configurable scoring and policy inputs.
- Report technical considerations alongside estimated financial outcomes.
- Produce structured JSON or human-readable Markdown output.
- Keep assessment separate from cluster mutation and deployment execution.
- Make assumptions, missing evidence, and estimation limits visible to reviewers.

---

# ✨ Key Features

## ☸️ Kubernetes Workload Analysis

- Reads Kubernetes YAML manifests from a directory when `yaml_directory` is selected.
- Supports an optional `kubernetes_api` input mode when the operator explicitly opts into cluster access and provides suitable credentials.
- Builds a structured inventory of supported Kubernetes workloads and their container resource declarations.
- Normalizes supported CPU and memory quantities for consistent analysis.
- Captures workload and namespace context used by downstream analysis.
- Provides a common inventory structure for capacity checks, cost estimation, and optimization scoring.
- Supports options for namespace filtering, completed jobs, invalid manifests, and maximum files, subject to the implemented CLI behavior.

Manifest analysis is the safer starting point for initial evaluation because it does not require connecting to a live cluster. A manifest describes declared configuration; it does not prove current utilization, actual node cost, or runtime performance.

## 📊 Capacity Analysis

- Checks supported resource request and limit configurations.
- Identifies missing or inconsistent resource declarations covered by the configured rules.
- Evaluates supported replica and workload-availability signals.
- Uses metrics or utilization evidence only when that evidence is available and supported by the implementation.
- Produces findings with severity, explanations, and review guidance.
- Helps distinguish configuration problems from opportunities that require runtime measurements.

A resource request is a scheduling declaration, not a direct measurement of consumption. Do not right-size production workloads from requests alone when reliable utilization, peak behavior, latency, throttling, and service-level objective data are required.

## 💰 Cost Simulation

- Loads pricing assumptions from `cost_policies.yaml`.
- Calculates estimated resource costs for supported inventory and pricing dimensions.
- Supports scenario comparison where baseline and proposed quantities can be evaluated with configured rates.
- Produces estimated savings or cost differences only when the required rates and resource data are available.
- Uses the policy's currency and pricing metadata where supported.
- Helps engineering teams compare options before a change is proposed.

**Cost disclaimer:** included rates are illustrative planning defaults. They are not live cloud-provider quotes, invoices, or guaranteed savings. Replace them with values appropriate to the cloud provider, region, node family, discounts, commitments, shared platform costs, and internal chargeback model. Validate the estimate against actual billing data before using it for budgets or financial commitments.

## 🧭 Optimization Engine

- Combines supported workload and capacity evidence into optimization opportunities.
- Scores and prioritizes recommendations using the information available to the implementation.
- Provides rationale and operational considerations for review.
- Helps compare possible right-sizing or resource-allocation scenarios.
- Supports a review-first workflow rather than applying changes automatically.
- Makes it easier to focus engineering effort on recommendations with meaningful potential value.

Recommendations are decision-support outputs, not guarantees. A recommendation should be validated against production traffic patterns, peak usage, application behavior, autoscaling policies, pod disruption budgets, topology constraints, and service-level objectives before implementation.

## 📈 Measurable Business Value

The simulator is designed to help teams express optimization proposals in both technical and financial terms, where the necessary data is available:

- Estimated monthly cost before and after a proposed scenario.
- Estimated cost difference and percentage savings for supported calculations.
- Annualized estimates derived from monthly assumptions where supported.
- Workload-level and aggregate opportunity summaries.
- Prioritized recommendations that can be reviewed by platform and application owners.
- Clear assumptions for finance or FinOps review.

The report's savings values are estimates based on the supplied policies and inventory. They should not be presented as realized savings until the changes are implemented, observed, and reconciled against actual billing data.

## 📄 Configuration-Driven Policies

- `config.yaml` defines application settings, input behavior, and analysis/reporting defaults.
- `cost_policies.yaml` defines the illustrative cost model and pricing metadata.
- `kubernetes_rules.yaml` defines starter capacity and optimization policy rules.
- Configuration files can be version-controlled and reviewed with code changes.
- Policy thresholds should be tuned to the organization's workloads, service-level objectives, and financial model.

A YAML rule only affects runtime behavior if the corresponding rule type and setting are implemented by the Python evaluator. Successful YAML parsing alone does not prove that every declared policy is enforced.

## 🧾 Reporting

- Supports JSON output for downstream automation and data processing.
- Supports Markdown output for human-readable reviews.
- Can write a report to a specified output path.
- Includes analysis, findings, cost estimates, and recommendations available from the selected input and implemented analyzers.
- Supports logging levels for operational troubleshooting.

Reports can contain infrastructure metadata. Store generated files securely and avoid publishing sensitive workload names, annotations, configuration values, or cluster details without review.

## 🛡️ Safety and Operational Boundaries

- Manifest-directory analysis does not require live cluster access.
- Kubernetes API access is an explicit opt-in mode, not an assumed default.
- The CLI exposes `--allow-cluster-access` for workflows that require cluster access.
- The project is designed to analyze and recommend, not to patch or deploy resources.
- Missing or uncertain evidence should be reviewed instead of treated as proof of safety.
- Human review remains necessary before production changes.

The cluster API mode should be run only with authorized contexts and least-privilege read permissions. Confirm the current implementation and Kubernetes RBAC configuration before connecting it to a production cluster.

---

# 🏗️ System Architecture

## Core Components

- **Main CLI (`main.py`):** parses command-line options, loads the configured policies, selects the input source, runs the analysis pipeline, and writes JSON or Markdown reports.
- **Kubernetes Analyzer (`kubernetes_analyzer.py`):** parses supported manifest inputs or supported Kubernetes inventory data and creates normalized workload/resource records.
- **Capacity Analyzer (`capacity_analyzer.py`):** evaluates supported resource configuration and capacity signals against capacity-related rules.
- **Cost Simulator (`cost_simulator.py`):** estimates costs from inventory and configured pricing assumptions and evaluates supported cost scenarios.
- **Optimization Engine (`optimization_engine.py`):** turns supported findings and scenario evidence into scored, prioritized recommendations.
- **`config.yaml`:** application and runtime configuration.
- **`cost_policies.yaml`:** cost rates, currency, and pricing assumptions.
- **`kubernetes_rules.yaml`:** capacity and optimization rule definitions.
- **`requirements.txt`:** Python package dependencies.

## High-Level Flow

```text
Kubernetes YAML Manifests
          |
          | or explicitly enabled Kubernetes API inventory
          v
Kubernetes Analyzer
          |
          v
Normalized Workload Inventory
          |
          +-----------------------+
          |                       |
          v                       v
Capacity Analyzer           Cost Simulator
          |                       |
          +-----------+-----------+
                      |
                      v
              Optimization Engine
                      |
                      v
          Prioritized Recommendations
                      |
                      v
             JSON / Markdown Report
```

The workflow generates analysis and recommendations. It does not automatically modify workloads or apply changes to a cluster.

---

# ⚙️ Technologies Used

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)
![PyYAML](https://img.shields.io/badge/PyYAML-CB171E?style=for-the-badge&logo=yaml&logoColor=white)
![JSON](https://img.shields.io/badge/JSON-Report_Formats-000000?style=for-the-badge&logo=json&logoColor=white)
![FinOps](https://img.shields.io/badge/FinOps-Cost_Analysis-2E8B57?style=for-the-badge)

## Technologies Included

- Python 3.11 or later recommended.
- PyYAML for YAML configuration and manifest parsing.
- Kubernetes Python client for the optional Kubernetes API integration.
- Python dataclasses and type annotations for structured inventory, findings, and recommendations.
- JSON for machine-readable output.
- Markdown for human-readable reports.
- `argparse` for the command-line interface.
- Logging for diagnostic output.

---

# 📁 File Structure

```text
capacity-and-cost-simulator/
│
├── README.md
├── requirements.txt
├── config.yaml
├── cost_policies.yaml
├── kubernetes_rules.yaml
├── main.py
├── kubernetes_analyzer.py
├── capacity_analyzer.py
├── cost_simulator.py
└── optimization_engine.py
```

## File Responsibilities

| File | Responsibility |
|---|---|
| `README.md` | Project overview, architecture, setup, usage, and limitations |
| `requirements.txt` | Python package dependencies |
| `config.yaml` | Application configuration and runtime defaults |
| `cost_policies.yaml` | Illustrative rates, currency, and cost-model assumptions |
| `kubernetes_rules.yaml` | Capacity, reliability, and optimization rule definitions |
| `main.py` | CLI, orchestration, report output, and error handling |
| `kubernetes_analyzer.py` | Workload inventory from supported manifest or cluster inputs |
| `capacity_analyzer.py` | Capacity checks and supported resource-configuration findings |
| `cost_simulator.py` | Cost estimates and supported scenario comparisons |
| `optimization_engine.py` | Optimization scoring, recommendation generation, and prioritization |

Runtime reports and logs may be created depending on the command and configuration. They are generated artifacts, not additional source files required by the ten-file project structure.

---

# ⚙️ Installation and Setup

## 1️⃣ Prerequisites

Install or prepare:

- Python 3.11 or later.
- `pip`.
- A terminal or command prompt.
- The ten project files listed above.
- Kubernetes YAML manifests for local analysis, or an authorized Kubernetes context if you intend to use the optional API mode.

## 2️⃣ Open the Project Directory

Open a terminal in the directory containing `main.py`, `requirements.txt`, `config.yaml`, `cost_policies.yaml`, and `kubernetes_rules.yaml`.

If you downloaded the Python modules and configuration files separately, place them together in the same project directory. Keep the expected filenames unchanged unless you also pass alternate paths through supported CLI arguments.

## 3️⃣ Create a Virtual Environment

### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 4️⃣ Install Dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The supplied dependency list includes PyYAML and the Kubernetes Python client. The Kubernetes client is needed for the optional API mode; manifest-only workflows can be run without granting cluster access, although dependencies are still installed by the standard requirements command.

## 5️⃣ Verify the Configuration Files

Confirm these files are present in the project root:

```text
config.yaml
cost_policies.yaml
kubernetes_rules.yaml
```

Run a YAML syntax check:

```bash
python -c "import yaml; from pathlib import Path; files=['config.yaml','cost_policies.yaml','kubernetes_rules.yaml']; [yaml.safe_load(Path(f).read_text(encoding='utf-8')) for f in files]; print('YAML files parsed successfully')"
```

This verifies that the files can be parsed as YAML. It does not verify that every rule is supported or that thresholds are appropriate for your workloads.

## 6️⃣ Check the CLI

```bash
python main.py --help
```

Review the available options before running an assessment. The CLI includes options for input source, manifest directory, configuration paths, environment, namespace, Kubernetes context and kubeconfig, explicit cluster-access acknowledgement, report format, output path, and log level.

---

# ▶️ Running the Project

## 1️⃣ Prepare Kubernetes Manifests

Create a directory for the YAML files you want to inspect. For example:

```text
capacity-and-cost-simulator/
├── manifests/
│   ├── deployment.yaml
│   ├── statefulset.yaml
│   └── namespace.yaml
├── config.yaml
├── cost_policies.yaml
├── kubernetes_rules.yaml
└── main.py
```

Use real, authorized manifests that reflect the workloads you want to assess. Do not assume the example filenames above must exist; the directory should contain the manifests you intend to analyze.

## 2️⃣ Run Manifest Analysis

Use the YAML-directory input mode:

```bash
python main.py --source yaml_directory --manifests ./manifests --environment development --format json --output ./reports/simulation.json
```

The command requests JSON output and writes the report to `./reports/simulation.json`. If the output directory does not exist and the application does not create it automatically, create it before running:

```bash
mkdir reports
```

For a human-readable report, use:

```bash
python main.py --source yaml_directory --manifests ./manifests --environment development --format markdown --output ./reports/simulation.md
```

Use `python main.py --help` to confirm the supported arguments and defaults for the version you have.

## 3️⃣ Optional: Kubernetes API Input

Use cluster input only when you have permission to inspect the target cluster. Review the active Kubernetes context and permissions before running any command that contacts a cluster.

The CLI exposes an explicit acknowledgement flag for cluster access. A typical invocation is:

```bash
python main.py --source kubernetes_api --allow-cluster-access --environment development --format json --output ./reports/cluster-assessment.json
```

If required, supply the supported `--context`, `--kubeconfig`, or `--namespace` options. Confirm exact behavior using `python main.py --help` and review the implementation before using this mode against a production cluster.

Use least-privilege credentials and read-only RBAC for inventory collection wherever possible. Do not provide write permissions merely to run an analysis.

## 4️⃣ Select an Environment

The CLI supports the environment labels:

```text
development
staging
production
```

Choose the label that matches the assessment context. An environment label is contextual metadata; it does not itself prove that the input is from that environment or enforce cluster access restrictions.

## 5️⃣ Review the Report

Inspect the generated JSON or Markdown report. Depending on available input and supported logic, the report may contain:

- Workload and resource inventory.
- Capacity findings and their severity.
- Resource requests, limits, and supported utilization evidence.
- Estimated costs based on configured rates.
- Supported before-and-after scenario comparisons.
- Optimization recommendations and priority scores.
- Explanations, assumptions, or missing-data indicators.

Review the evidence and assumptions for every proposed optimization. Do not use a cost estimate as an invoice or a recommendation as automatic authorization to change production.

---

# 🔄 System Workflow

### 1️⃣ Input Collection

The application reads Kubernetes manifests from a directory or uses the explicitly enabled API input path.

### 2️⃣ Inventory Normalization

The Kubernetes analyzer parses supported resources and normalizes supported resource quantities into structured workload records.

### 3️⃣ Capacity Assessment

The capacity analyzer evaluates supported requests, limits, replica settings, and other configured signals. Findings depend on both the supplied inventory and the rules implemented by the evaluator.

### 4️⃣ Cost Estimation

The cost simulator applies configured pricing assumptions to the supported resource quantities. Unknown rates or missing data may limit which costs can be estimated reliably.

### 5️⃣ Optimization Evaluation

The optimization engine evaluates supported opportunities and prioritizes recommendations using the evidence and scoring logic available in the current implementation.

### 6️⃣ Report Generation

The CLI produces a JSON or Markdown report for technical and business review.

### 7️⃣ Human Review and Validation

Platform and application owners validate the recommendation against real usage, reliability requirements, and billing data before deciding whether to implement it.

---

# 🧪 Validation and Testing

Before using the simulator to support production decisions, validate it with representative manifests and known expected outcomes.

## Recommended Validation Checklist

- Confirm all ten project files are present.
- Install dependencies in a clean virtual environment.
- Parse all three YAML configuration and policy files successfully.
- Run `python main.py --help`.
- Test a small manifest directory containing a Deployment with CPU and memory requests and limits.
- Test a manifest with missing resource declarations.
- Test multiple containers and multiple replicas.
- Test supported resource quantities such as millicores and memory units.
- Test invalid YAML and confirm the selected error-handling behavior.
- Test empty directories and unsupported resource kinds.
- Test namespace filtering and ignored-namespace behavior where configured.
- Test the cost simulator with known, manually calculated sample rates.
- Confirm currency and pricing assumptions are consistent across the policy file.
- Test recommendations where metrics are absent and ensure missing evidence is not mistaken for zero utilization.
- Test JSON and Markdown output.
- Review output for sensitive data before sharing it.
- If using API mode, verify that the identity has only the required permissions and that the intended context and namespace are selected.
- Add automated unit and integration tests before relying on the results for production decisions.

A successful command or valid YAML file does not establish that an optimization is safe, that every policy is enforced, or that estimated savings will be realized. Validate calculations against known fixtures and compare estimates with actual billing and runtime metrics.

---

# 🛡️ Configuration and Security Notes

- Review `config.yaml`, `cost_policies.yaml`, and `kubernetes_rules.yaml` before using the project in a shared engineering workflow.
- Keep policy files under version control and review policy changes.
- Calibrate cost rates to the relevant provider, region, instance or node family, discounts, commitments, and chargeback model.
- Treat cluster names, namespaces, workload metadata, annotations, and generated reports as potentially sensitive.
- Do not commit kubeconfig files, credentials, tokens, production manifests, or sensitive report output.
- Use least-privilege access for optional Kubernetes API collection.
- Prefer manifest-only analysis when live cluster information is not needed.
- Do not grant write permissions to a read-only assessment workflow.
- Require workload-owner review before applying resource or replica changes.
- Validate recommendations against peak traffic, latency, error rates, memory peaks, CPU throttling, autoscaling behavior, disruption budgets, and service-level objectives.
- Compare estimates with billing exports before reporting realized financial impact.
- Keep deployment and mutation permissions in a separate, reviewed workflow.

**Important:** the simulator is an analysis and decision-support tool. It is not a replacement for Kubernetes admission controls, policy enforcement, observability, load testing, FinOps billing reconciliation, or a controlled deployment process.

---

# ⚠️ Current Scope and Limitations

- Cost rates are illustrative until calibrated to actual provider and organization pricing.
- Estimated costs may not include every real-world charge, such as control-plane fees, network egress, persistent storage details, support plans, taxes, shared platform overhead, or commitment effects, unless those costs are explicitly modeled.
- Manifest input represents declared configuration, not live resource utilization.
- Utilization-based rightsizing requires reliable metrics and an appropriate observation window.
- Kubernetes API mode depends on the implemented client behavior, current context, credentials, and RBAC permissions.
- Only the Kubernetes kinds, resource fields, and policy rule types implemented by the Python modules can affect the analysis.
- A rule in YAML is not enforced merely because it exists in a policy file.
- Recommendations are not automatically applied to a cluster.
- Potential savings are estimates, not guaranteed or realized savings.
- The report should not be treated as a substitute for performance testing, reliability review, or finance validation.
- Automated test coverage should be established before the project is used as a production governance control.

---

# 🚀 Future Improvements

- Integrate historical Prometheus or another approved metrics source for utilization-aware recommendations.
- Add richer workload and node capacity modeling.
- Support provider- and region-specific pricing catalogs.
- Reconcile estimated savings against cloud billing exports.
- Add explicit cost modeling for persistent volumes, network traffic, node pools, commitments, and shared services.
- Improve workload criticality and service-level objective awareness.
- Add unit, integration, and regression tests with representative Kubernetes fixtures.
- Add confidence scores and data-freshness indicators to utilization-based recommendations.
- Improve support for autoscalers, disruption budgets, affinity, topology spread, and scheduling constraints.
- Add recommendation export formats for pull requests or change-management tickets.
- Add authenticated approval workflows before any external system can apply a recommendation.
- Add optional policy integrations for established Kubernetes security and governance tools.
- Add dashboarding for estimated savings, implemented changes, and realized cost impact.
- Improve report redaction and configurable retention.

---

# 🌍 Potential Use Cases

### ☸️ Kubernetes Resource Right-Sizing

Identify supported configuration and capacity signals that may justify reviewing CPU or memory allocations.

### 💰 FinOps and Cloud Cost Planning

Estimate the potential financial effect of supported resource scenarios using organization-reviewed rates.

### 🧰 Platform Engineering

Provide a repeatable analysis workflow for workload owners and platform teams.

### 📋 Engineering Change Review

Attach a structured report to a change request so technical risks and estimated value can be reviewed before implementation.

### 📊 Business Value Reporting

Translate supported resource changes into estimated monthly or annual cost differences, with assumptions clearly stated.

### 🔍 Pre-Deployment Analysis

Review manifests before applying them to a cluster, without requiring the simulator itself to modify infrastructure.

---

# 🏁 Conclusion

Capacity and Cost Simulator provides a Python-based foundation for Kubernetes workload analysis, capacity assessment, cost estimation, and optimization prioritization. It brings technical findings and estimated business value into a structured JSON or Markdown report, while keeping analysis separate from deployment.

The project is intended to help teams make better-informed decisions, not to promise automatic savings or guarantee operational safety. Before production use, validate policy behavior, calibrate rates to actual pricing, supply reliable utilization evidence, add automated tests, protect reports and credentials, and require workload-owner review before implementing changes.
