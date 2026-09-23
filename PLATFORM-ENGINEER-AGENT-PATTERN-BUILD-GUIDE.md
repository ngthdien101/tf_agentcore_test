# Platform Engineer Agent Pattern Build Guide

## Purpose

This guide describes the recommended order for a platform engineer to build a reusable Agentic AI application platform from scratch. It complements the reusable-pattern development guide by focusing on platform deliverables, application-team dependencies, and completion evidence.

The reference implementation is `data-ai-genai-platform-agentic-gw-pattern`.

## Build sequence

```text
Platform boundary
  → Consumer contract
  → Delivery foundation
  → Identity and security
  → Gateway and runtime
  → Tool execution boundary
  → Observability
  → Evaluation gates
  → Resilience and cost controls
  → Reference application
  → Independent reuse
  → Operating model
```

The platform engineer should establish the contract, controls, and runtime boundary before attempting to generalise prompts or application workflows.

## 1. Define the platform boundary

### Inputs

- Target users and agent use cases.
- Business outcomes and constraints.
- Security, privacy, and regulatory requirements.
- Expected adoption and support model.

### Platform engineer delivers

- Reference architecture.
- Platform/application responsibility matrix.
- Supported and unsupported use cases.
- Trust boundaries.
- Initial threat model.
- Ownership and escalation model.

### AI engineer contributes

- User scenarios.
- Agent responsibilities.
- Domain constraints.
- Unacceptable outcomes.
- Human approval and escalation requirements.

### Completion evidence

Both engineers agree what the platform owns, what the application owns, and which actions require human involvement.

## 2. Define the consumer contract

### Inputs

- Responsibility matrix.
- Reference use case.
- Identity and data requirements.
- Required integrations.

### Platform engineer delivers

- Agent registration interface.
- Runtime configuration schema.
- Authentication and authorisation contract.
- Tool registration and invocation interface.
- Standard request/response schemas.
- Error, timeout, retry, and refusal semantics.
- Configuration, secret, and telemetry contracts.
- Compatibility and versioning rules.

### AI engineer contributes

- Prompt and context requirements.
- Tool input/output schemas.
- Knowledge-source requirements.
- Expected agent responses.
- Domain-specific error and escalation behaviour.

### Completion evidence

The contract is versioned, documented, and usable without exposing platform implementation details.

## 3. Establish the delivery foundation

### Inputs

- Consumer contract.
- Environment model.
- Release and promotion strategy.

### Platform engineer delivers

- Repository structure separating platform modules and examples.
- CI/CD pipeline.
- Infrastructure format, validation, lint, security, and policy checks.
- Environment promotion path.
- Terraform state and artifact management.
- Secret and configuration management.
- Release versioning and changelog process.
- Rollback mechanism.

### AI engineer contributes

- Application configuration model.
- Prompt/tool/evaluation versioning approach.
- Required deployment parameters.
- Application smoke tests.

### Completion evidence

A new environment can be deployed repeatedly through the pipeline with no manual platform intervention beyond approved controls.

## 4. Build the identity and security baseline

### Inputs

- Threat model.
- Data classification.
- Target cloud accounts and environments.
- Required model, tool, and data access.

### Platform engineer delivers

- Workload identities.
- Least-privilege IAM roles and policies.
- Separation of platform, application, and user permissions.
- Secret storage and rotation.
- Encryption and key management.
- Network boundaries and controlled egress.
- Environment and consumer isolation.
- Audit logging.
- Access-review process.

### AI engineer contributes

- Prompt, context, memory, and output data classification.
- Approved data sources.
- Sensitive-data redaction and minimisation rules.
- Prompt-injection and indirect-instruction scenarios.
- Unsafe-action and tool-abuse scenarios.

### Completion evidence

The complete chain has been reviewed:

```text
User → Gateway → Agent → Model → Tool → Data or downstream system
```

No critical security finding remains without an approved mitigation.

## 5. Build the gateway and runtime foundation

### Inputs

- Consumer contract.
- Identity and security baseline.
- Runtime and model requirements.

### Platform engineer delivers

- Standard gateway entry point.
- Request authentication and authorisation.
- Correlation ID propagation.
- Agent routing and configuration loading.
- Model/provider integration boundary.
- Context and memory boundaries.
- Payload validation.
- Request limits.
- Standard error handling.
- Health and readiness checks.

### AI engineer contributes

- Agent instructions and workflow.
- Context requirements.
- Model selection criteria.
- Domain-specific response rules.
- Expected fallback and refusal behaviour.

### Completion evidence

A reference agent can be deployed through the platform without modifying shared runtime internals.

## 6. Build the tool execution boundary

### Inputs

- Approved agent actions.
- Downstream APIs.
- Authorisation model.
- Tool risk classification.

### Platform engineer delivers

- Tool registration mechanism.
- Typed tool interface.
- Tool-level authorisation.
- Input validation.
- Timeout and retry controls.
- Idempotency or duplicate-action protection.
- Rate limits and quotas.
- Audit events.
- Human approval hooks.
- Safe failure responses.

### AI engineer contributes

- Tool purpose and domain behaviour.
- Tool descriptions and selection guidance.
- Input/output definitions.
- Domain validation.
- Tests for correct and incorrect tool selection.

### Completion evidence

Every tool invocation is authorised, bounded, observable, and independently testable.

## 7. Build observability as a platform capability

### Inputs

- Operational requirements.
- SLOs.
- Support model.
- Privacy and retention rules.

### Platform engineer delivers

- Structured logging standard.
- Correlation and trace propagation.
- Common metrics.
- Dashboards and alerts.
- Usage and cost telemetry.
- Tool execution telemetry.
- Retention and access controls.
- Operational runbooks.

### AI engineer contributes

- Business success metrics.
- Useful diagnostic context.
- Application failure modes.
- Domain-specific alert thresholds.
- Support and troubleshooting information.

### Completion evidence

Operations can determine whether a failure came from the gateway, model, prompt/workflow, tool, data source, or downstream dependency.

## 8. Build the evaluation and quality-gate framework

### Inputs

- Evaluation datasets.
- Security scenarios.
- Threat model.
- Contract and operational requirements.

### Platform engineer delivers

- Reusable evaluation harness.
- Infrastructure validation.
- IAM and policy checks.
- Contract compatibility tests.
- Deployment smoke tests.
- Security regression gates.
- Performance and quota tests.
- Pipeline result reporting.

### AI engineer contributes

- Golden test datasets.
- Task-success metrics.
- Factuality and groundedness tests.
- Prompt-injection and unsafe-request tests.
- Tool-selection and argument tests.
- Regression thresholds.

### Completion evidence

Platform changes cannot be released when they break the contract or mandatory security gates. Application changes cannot be promoted without passing agreed AI quality and safety thresholds.

## 9. Build resilience, scaling, and cost controls

### Inputs

- Usage forecast.
- SLOs.
- Dependency limits.
- Cost targets.

### Platform engineer delivers

- Timeout and retry policies.
- Failure isolation or circuit breaking.
- Concurrency limits.
- Queuing where required.
- Rate limiting and quotas.
- Provider fallback controls.
- Cost tagging and attribution.
- Usage dashboards.
- Recovery and outage runbooks.

### AI engineer contributes

- Context and prompt optimisation.
- Model selection and fallback behaviour.
- Tool sequencing optimisation.
- Quality/cost trade-offs.
- Degraded-mode application behaviour.

### Completion evidence

The pattern has measurable latency, throughput, cost, quota, and degraded-mode behaviour.

## 10. Build the reference application path

### Inputs

- Stable platform contract.
- Working runtime and tool boundary.
- Evaluation and observability capability.

### Platform engineer delivers

- Standard onboarding path.
- Reference infrastructure configuration.
- Example dashboards and alerts.
- Deployment and troubleshooting guidance.
- Platform integration tests.

### AI engineer contributes

- Complete reference agent.
- Example prompts and workflows.
- Example tool integration.
- Evaluation dataset.
- Known limitations.

### Completion evidence

The reference application uses only documented interfaces and can be deployed by a new team without platform source-code changes.

## 11. Prove independent reuse

### Inputs

- Reference pattern.
- Reference application evidence.
- Candidate adopter use case.

### Platform engineer delivers

- Compatibility test.
- Consumer isolation validation.
- Upgrade and rollback test.
- Platform remediation backlog.
- Adoption support.

### AI engineer contributes

- Independent agent scenario.
- Application configuration.
- New evaluation evidence.
- Adopter feedback.

### Completion evidence

An independent consumer can adopt the pattern without forking core platform components.

## 12. Establish the operating model

### Inputs

- Production evidence.
- Ownership decisions.
- Support requirements.
- Security and operations approvals.

### Platform engineer delivers

- Support boundary.
- SLOs and escalation model.
- Incident response process.
- Release and deprecation policy.
- Upgrade and migration guides.
- Security review cadence.
- Cost and usage review.
- Platform health reporting.

### AI engineer contributes

- Application support runbook.
- Business-impact assessment.
- Quality and safety trend reporting.
- Prompt/tool/data change process.
- Retirement or migration requirements.

### Completion evidence

The pattern has an accepted owner, support path, lifecycle policy, and evidence-based reuse decision.

## Platform engineer priority rule

Build the reusable control plane first:

1. Contract and boundaries.
2. Identity and security.
3. Deployment and environment promotion.
4. Gateway and runtime controls.
5. Tool execution policy.
6. Observability and operations.
7. Evaluation and quality gates.
8. Resilience, quotas, and cost controls.
9. Reference application and independent adoption.

The platform should make the safe, observable, and supportable path the easiest path for AI engineers to use.
