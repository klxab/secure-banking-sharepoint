# Secure Banking Information System

## 1. Project Overview

**Thesis title:** Design and Implementation of a Secure SharePoint-Based Banking Information System with Role-Based Access Control, Data Tokenization and Access Anomaly Detection

**Repository:** `secure-banking-sharepoint`

This project will develop and evaluate a security-focused prototype for managing simulated banking information through a SharePoint-based architecture.

The system will combine access control, data tokenization, audit logging and access anomaly detection. All development and experiments will use synthetic banking data.

## 2. Research Objectives

1. Implement role-based access control (RBAC) for banking information.
2. Protect sensitive fields using data tokenization.
3. Record access events in a structured audit log.
4. Develop a sensitivity-aware, role-conditioned access anomaly detection approach.
5. Compare the proposed approach against rule-based detection and an Isolation Forest baseline.
6. Evaluate detection performance, false positives, security controls and system overhead.

## 3. Planned Architecture

### SharePoint Integration
SharePoint Online will serve as the document-management platform, subject to account capabilities and licensing.

### Backend API
Python and FastAPI will provide application endpoints and coordinate security checks.

### Data Storage
PostgreSQL will store application metadata, token mappings and audit events, with access restrictions appropriate to each data type.

### Access Control
RBAC will enforce permissions based on user roles and requested actions.

### Data Tokenization
Sensitive identifiers will be replaced with tokens. Access to the original values will be restricted to an authorized tokenization service.

### Anomaly Detection
A Python-based detection pipeline will analyze access events using role context, resource sensitivity and behavioral features.

### Evaluation
Experiments will use synthetic data and controlled access scenarios. Results will be compared against defined baselines.

## 4. Security Principles

- Least-privilege access.
- Separation of duties.
- Synthetic data only during development and evaluation.
- No secrets, credentials or tokens committed to Git.
- Server-side authorization for protected operations.
- Restricted access to token mappings.
- Auditable security-relevant events.
- Reproducible experiments and documented configuration.

## 5. Implementation Constraints

The available Microsoft account, SharePoint capabilities, Microsoft Graph permissions, Azure access and licensing must be verified before selecting the final integration method.

The core security mechanisms should be developed and tested independently where practical, so that cloud-access limitations do not block progress.

## 6. Research Contribution

The proposed contribution is a sensitivity-aware, role-conditioned anomaly detection and response mechanism for access to banking information.

Its value must be established experimentally against simpler baselines. The novelty claim will be refined after the literature review and must not be treated as proven before evaluation.

## 7. Current Status

**Phase:** Initial project setup.

**Completed:** GitHub repository created, Git installed and verified, Git Credential Manager version checked, VS Code installed and verified, initial documentation folders created.

**Next:** Verify the development environment, establish the final repository structure, implement the core security components and prepare reproducible tests.
