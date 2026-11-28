# Secure Banking Information System

## 1. Project overview

**Thesis title:** Design and Implementation of a Secure SharePoint-Based Banking Information System with Role-Based Access Control, Data Tokenization and Access Anomaly Detection

This research project develops a security-focused prototype for managing simulated banking information. The intended solution combines identity and access management, SharePoint integration, tokenization, structured audit logging and access anomaly detection.

**Data policy:** Development and experiments use synthetic data only.

## 2. Research objectives

1. Implement role-based access control (RBAC) for banking information.
2. Protect sensitive fields using data tokenization.
3. Record access events in a structured audit log.
4. Develop a sensitivity-aware, role-conditioned access anomaly detection approach.
5. Compare the proposed approach against rule-based detection and an Isolation Forest baseline.
6. Evaluate detection performance, false positives, security controls and system overhead.

## 3. Architecture and implementation status

### Implemented local security foundation

The current implementation consists of:
- FastAPI application and API routes for authentication and RBAC.
- PostgreSQL persistence using SQLAlchemy and Psycopg.
- Alembic migrations for the current schema.
- Argon2id password hashing.
- Session management using hashed token storage, expiry and revocation.
- Role/permission authorization checks.
- Structured audit logging for security-relevant events.

The implemented database currently includes `users`, `roles`, `permissions`, `user_roles`, `role_permissions`, `user_sessions` and `audit_logs`.

### Planned components

#### SharePoint integration

SharePoint Online is a planned document-management integration, subject to the capabilities of the available Microsoft 365 account, licensing and Microsoft Graph permissions. The core security mechanisms are being developed independently so cloud access limitations do not block local testing.

#### Banking domain

Customer, account, transaction and ledger models are planned. These entities are not part of the current database schema.

#### Tokenization

A dedicated tokenization service and restricted token vault are planned. Sensitive identifiers will be replaced by opaque tokens, and access to original values will be limited and audited.

#### Anomaly detection

A Python-based research pipeline will analyze access events using actor role, resource sensitivity and behavioral features. It will be compared with rule-based detection and Isolation Forest using synthetic scenarios.

## 4. Security principles

- Least-privilege access.
- Separation of duties.
- Deny-by-default authorization.
- Synthetic data only.
- Server-side authorization for protected operations.
- Restricted access to future token mappings.
- Auditable security-relevant events.
- Reproducible experiments and documented configuration.

The current implementation does not yet provide complete resource-ownership and sensitivity-aware authorization. Audit logs are structured but not tamper-proof. CSRF protection and production deployment hardening also remain outstanding.

## 5. Implementation constraints

The available Microsoft account, SharePoint capabilities, Microsoft Graph permissions, Azure access and licensing must be verified before selecting the final integration method.

The local application currently uses PostgreSQL, with Docker Compose available as an optional deployment method. Runtime application credentials and dedicated migration credentials are configured separately.

## 6. Research contribution

The proposed contribution is a sensitivity-aware, role-conditioned anomaly detection and response mechanism for access to banking information. Its value must be established experimentally against simpler baselines. The novelty claim will be refined after the literature review and must not be treated as proven before evaluation.

## 7. Current status

**Phase:** Core identity, authentication, authorization and audit foundations implemented; banking-specific security features remain under development.

**Completed implementation:**
- PostgreSQL and SQLAlchemy integration.
- Alembic migrations.
- IAM schema and seeded roles/permissions.
- Argon2id authentication and session lifecycle.
- FastAPI authentication and RBAC endpoints.
- Structured security audit events.
- Automated tests for the implemented components.

**Next development steps:**
1. Complete contextual authorization, including resource ownership and sensitivity.
2. Harden audit integrity and add CSRF protection where applicable.
3. Implement banking-domain entities using synthetic data.
4. Design and implement tokenization and token-vault controls.
5. Build the anomaly detection pipeline and baseline experiments.
6. Verify Microsoft 365 / SharePoint integration feasibility and implement the selected approach.
7. Complete evaluation and document limitations.

For setup instructions and links to the detailed technical documents, see the [repository README](../README.md).
