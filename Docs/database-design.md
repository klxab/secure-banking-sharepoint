# Database Design

## 1. Purpose

The database supports a secure banking information system prototype
designed for research into role-based access control, data
tokenization, security auditing, and access anomaly detection.

The system uses synthetic data exclusively.

## 2. Database Technology

- Database: PostgreSQL
- Version: 17.11
- Development deployment: Docker
- Database name: banking_dev
- Database application user: banking_app
- Local host port: 5433
- ORM: SQLAlchemy
- Database driver: Psycopg 3

## 3. Architectural Principles

- Least privilege
- Deny-by-default authorization
- Separation of duties
- Defense in depth
- Data minimization
- Secure handling of sensitive information
- Auditability
- Database integrity
- Reproducible testing
- Synthetic data only

## 4. Planned Database Entities

### Identity and Access Management

- users
- roles
- permissions
- user_roles
- role_permissions
- sessions

### Banking Domain

- customers
- accounts
- banking_transactions
- ledger_entries

### Security

- token_vault
- security_events

## 5. Authorization Model

The system uses Role-Based Access Control (RBAC).

Permissions are assigned to roles, and roles are assigned to users.

Authorization will additionally consider contextual factors such as
resource ownership, resource sensitivity, requested action, and
purpose of access where applicable.

The authorization policy follows a deny-by-default principle.

Initial roles:

- system_admin
- security_officer
- bank_analyst
- customer_support
- customer
- auditor

Administrative privileges do not automatically grant unrestricted
access to sensitive banking data.

## 6. Banking Data Design

Customers and accounts will use pseudonymous identifiers.

Accounts will not expose sensitive identifiers directly to ordinary
application components.

Financial transactions will use a ledger-based design with debit
and credit entries.

Financial integrity requirements will include:

- Positive transaction amounts
- Valid currency codes
- Referential integrity
- Transactional processing
- Balanced ledger operations
- Protection against unauthorized modification

## 7. Tokenization Design

Sensitive identifiers will be replaced with opaque tokens.

The token vault will store protected mappings between tokens and
sensitive values.

Sensitive values will be encrypted using authenticated encryption.

Encryption keys will be stored outside the database and outside Git.

The design will support key versioning and future key rotation.

Vault access will be restricted and audited.

## 8. Security Event Logging

Security events will record relevant events such as:

- Authentication attempts
- Authorization decisions
- Sensitive data access
- Denied access
- Role and permission changes
- Tokenization and de-tokenization operations
- Security-related system activity

Logs must not contain passwords, encryption keys, or raw sensitive
banking identifiers.

Security events will support the anomaly detection research.

## 9. Anomaly Detection Research

The research will investigate role-conditioned and sensitivity-aware
access anomaly detection.

The planned comparison includes:

- Rule-based detection
- Isolation Forest
- Proposed role-conditioned and sensitivity-aware detection

Experiments will use synthetic datasets and controlled scenarios.

Evaluation metrics will include:

- Precision
- Recall
- F1-score
- False-positive rate
- Detection latency

## 10. Implementation Status

This document describes the planned database design.

The database schema and entities have not yet been implemented.

Implementation decisions will be reviewed and tested before being
considered complete.