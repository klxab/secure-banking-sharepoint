# Database Design

## 1. Purpose

The database supports a security-focused banking information system prototype for research into role-based access control, data tokenization, security auditing and access anomaly detection. Development and evaluation use synthetic data only.

This document distinguishes the **implemented persistence layer** from the **planned banking-domain design**.

## 2. Database technology

- Database: PostgreSQL
- Current recorded local server: PostgreSQL 17.12
- Local development database: `banking_dev`
- Application database user: `banking_app`
- Local host port: `5433`
- ORM: SQLAlchemy
- Driver: Psycopg 3
- Schema migrations: Alembic

The current development setup uses a locally installed PostgreSQL server. The application connects to it through the host and port configured in the local `.env` file.

## 3. Implemented schema

The current application schema contains seven tables:

- `users`
- `roles`
- `permissions`
- `user_roles`
- `role_permissions`
- `user_sessions`
- `audit_logs`

These tables support user identity, role/permission assignment, authenticated sessions and structured security audit events. The exact columns and relationships are documented in [iam-schema.md](iam-schema.md), which includes the current ER diagram.

## 4. Database principles

- Least privilege
- Deny-by-default authorization
- Separation of duties
- Defense in depth
- Data minimization
- Secure handling of sensitive information
- Auditability
- Referential integrity
- Reproducible testing
- Synthetic data only

## 5. Planned banking-domain entities

The following entities are design targets and **are not implemented as database tables yet**:

- `customers`
- `accounts`
- `banking_transactions`
- `ledger_entries`

The future banking domain will use pseudonymous identifiers where appropriate. Account and transaction operations will require explicit authorization checks, ownership validation and transactional integrity.

Financial integrity requirements to address include:
- Positive transaction amounts and valid currency codes
- Referential integrity
- Atomic transaction processing
- Balanced debit and credit ledger entries
- Protection against unauthorized modification

## 6. Planned tokenization design

A future `token_vault` component will maintain protected mappings between opaque tokens and sensitive values. Tokenization/de-tokenization operations will be restricted to a dedicated service and audited. Sensitive values should be encrypted using authenticated encryption; keys must be managed outside the database and Git. Key versioning and rotation will be addressed in the implementation design.

No token vault or tokenization table is currently implemented.

## 7. Security event logging

The implemented `audit_logs` table records fields including actor, action, outcome, target, request metadata, JSON details and event timestamp. It is used for security-relevant authentication and authorization events.

Future event coverage will be extended as banking data access, tokenization and anomaly detection components are added. Logs must not contain passwords, session secrets, encryption keys or raw sensitive banking identifiers.

The current audit log is structured but is not yet tamper-proof. Database-level append-only controls and independent integrity verification remain future hardening work.

## 8. Anomaly detection research

The research will investigate sensitivity-aware, role-conditioned access anomaly detection.

Planned comparison:
- Rule-based detection
- Isolation Forest
- Proposed role-conditioned and sensitivity-aware detection

Experiments will use synthetic datasets and controlled access scenarios. Planned evaluation metrics include precision, recall, F1-score, false-positive rate and detection latency.

No anomaly detection pipeline or evaluation results are implemented yet.

## 9. Implementation status summary

| Area | Status |
|---|---|
| IAM tables and relationships | Implemented |
| Session persistence | Implemented |
| Structured audit logs | Implemented |
| Banking customers and accounts | Planned |
| Transactions and ledger | Planned |
| Token vault and tokenization | Planned |
| Anomaly detection data pipeline | Planned |

The implemented schema is defined by the SQLAlchemy models in `src/models/` and the Alembic migrations in `alembic/versions/`.
