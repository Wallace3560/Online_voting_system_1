# System Code Documentation

This document provides grouped documentation for the full Online Voting System codebase.

## 1. System Architecture Groups

### 1.1 Core Runtime and Shared Services
- `includes/db_connect.php`
  - Group A: Secure session initialization and cookie policy.
  - Group B: Environment-based DB config resolution.
  - Group C: Host/user/password/database fallback connection strategy.
  - Group D: Auto-create DB fallback and charset initialization.
- `includes/functions.php`
  - Group A: Wrapper imports and shared utility availability guards.
  - Group B: Location reference data access helpers.
  - Group C: User lookup utility helpers.
- `function.php`
  - Group A: Security headers and app-wide security utilities.
  - Group B: Email and SMTP dispatch layer.
  - Group C: Voter account lifecycle utilities (register/verify/reset/login checks).
  - Group D: Admin account lifecycle utilities and permissions.
  - Group E: Election schema bootstrap and maintenance helpers.
  - Group F: Candidate, ballot, vote-casting, and by-election logic.
  - Group G: Results aggregation, turnout analytics, location filtering.
  - Group H: Archive, audit logging, and operational controls.

### 1.2 Entry Pages and Controllers (Top-Level PHP)
- `index.html`
  - Group A: Public landing and navigation gateway.
- `register.php`, `login.php`, `forgot_password.php`, `reset_password.php`, `verify_email.php`, `resend_verification.php`, `check_verification.php`
  - Group A: Request validation and token checks.
  - Group B: Voter identity/auth/reset flow orchestration.
  - Group C: Message/error states and view rendering.
- `voter_account.php`, `change_location.php`, `voter_logout.php`
  - Group A: Authenticated voter profile and location change workflow.
  - Group B: Approval-dependent updates and request history.
- `ballot.php`
  - Group A: Session/auth gate and election-window checks.
  - Group B: Main ballot submission and by-election submission handlers.
  - Group C: Progress/steps generation and scoped ballot assembly.
- `results.php`
  - Group A: Results visibility policy.
  - Group B: Location filter intake (county/constituency/ward).
  - Group C: Filtered results/turnout data assembly.
  - Group D: View data payload and flash messaging.

### 1.3 Admin Controllers
- `admin_login.php`, `admin_logout.php`, `admin_forgot_password.php`, `admin_reset_password.php`
  - Group A: Admin auth entry, MFA flow, and secure session state.
  - Group B: Logout and re-auth enforcement.
  - Group C: Password reset and token workflows.
- `admin_verify_voters.php`
  - Group A: Role-based access and capability flags.
  - Group B: Voter verification and profile change approval actions.
  - Group C: Election controls, schedule, publish/hide controls.
  - Group D: Candidate and manual-vote operational actions.
  - Group E: Dashboard dataset loading.
- `admin_manage_voters.php`, `admin_records.php`
  - Group A: Administrative corrections/update actions.
  - Group B: Candidate status actions and reason enforcement.
  - Group C: Record filtering and table datasets.
- `admin_candidate_change_history.php`
  - Group A: Filtered change history retrieval.
  - Group B: CSV export pipeline.
- `sub_admin_dashboard.php`, `election_officer_dashboard.php`
  - Group A: Role-specific operational subset.
  - Group B: Manual vote intake and reviewer workflows.

### 1.4 API Endpoints
- `api/get_constituencies.php`
  - Group A: County parameter validation.
  - Group B: DB-backed constituency JSON response.
- `api/get_wards.php`
  - Group A: Constituency parameter validation.
  - Group B: DB-backed ward JSON response.

## 2. View Templates (`views/`)

### 2.1 Voter-Side Views
- `views/register.view.html`
  - Group A: Registration form layout and required fields.
  - Group B: Dynamic location selectors and validation messaging.
- `views/login.view.html`, `views/forgot_password.view.html`, `views/reset_password.view.html`, `views/verify_email.view.html`, `views/resend_verification.view.html`, `views/check_verification.view.html`
  - Group A: Auth/verification form structures.
  - Group B: Success/error information panels.
- `views/voter_account.view.html`, `views/change_location.view.html`
  - Group A: Profile-change and relocation request forms.
  - Group B: Existing requests/status history tables.
- `views/ballot.view.html`
  - Group A: Election status and voter progress panels.
  - Group B: Main ballot/by-election vote sections.
  - Group C: Sequential step UI, lock/unlock behavior scripts.
- `views/results.view.html`
  - Group A: Location filtering controls.
  - Group B: Turnout summary blocks.
  - Group C: Per-position candidate tables with photos and gaps.
  - Group D: Photo preview modal and dependent dropdown scripts.

### 2.2 Admin Views
- `views/admin_login.view.html`, `views/admin_forgot_password.view.html`, `views/admin_reset_password.view.html`
  - Group A: Admin auth/MFA/reset interfaces.
- `views/admin_verify_voters.view.html`
  - Group A: Dashboard stats and election control zones.
  - Group B: Verification queues and action forms.
  - Group C: Location-change requests, archive/reset, manual vote sections.
- `views/admin_manage_voters.view.html`, `views/admin_records.view.html`
  - Group A: Record tables and edit/correction forms.
  - Group B: Candidate management modal/actions.
- `views/admin_candidate_change_history.view.html`
  - Group A: Filter controls, data table, export controls.
- `views/sub_admin_dashboard.view.html`, `views/election_officer_dashboard.view.html`
  - Group A: Restricted operations, queues, and manual batch sections.

## 3. Frontend Assets

### 3.1 JavaScript (`assets/js/`)
- `assets/js/global_menu.js`
  - Group A: Global heading and navigation menu injection.
  - Group B: Role-home routing and link generation.
  - Group C: Admin tab-nonce propagation for secure navigation.
- `assets/js/admin_verify_voters.js`
  - Group A: Scope-dependent location selector behavior.
  - Group B: Dynamic by-election candidate row controls.
  - Group C: Candidate edit/manage interaction helpers.
- `assets/js/registration.js`
  - Group A: Dynamic county/constituency/ward loading.
  - Group B: Client-side registration form validations.

### 3.2 CSS (`assets/css/`)
- `assets/css/global_menu.css`
  - Group A: Global floating navigation and panel styles.
  - Group B: Commission heading visual identity styles.
- `assets/css/index.css`, `assets/css/styles.css`
  - Group A: Shared base theme and global component styling.
- `assets/css/views/*.css`
  - Group A: Page-specific layout and visual hierarchy.
  - Group B: Form/table components and responsive behavior.
  - Group C: Contextual enhancements (badges, candidate cards, modal visuals).

## 4. Functional Group Quick Map

### 4.1 Authentication and Session Security
- Voter auth flow: `login.php`, `voter_logout.php`, `includes/db_connect.php`, `function.php`.
- Admin auth + MFA flow: `admin_login.php`, `admin_logout.php`, `function.php`, `assets/js/global_menu.js`.

### 4.2 Election Operations
- Election schedule, publish/hide, archive/reset: `admin_verify_voters.php`, `function.php`, `views/admin_verify_voters.view.html`.
- Candidate lifecycle: `admin_verify_voters.php`, `admin_records.php`, `function.php`, admin views.

### 4.3 Voting and Results
- Ballot casting: `ballot.php`, `function.php`, `views/ballot.view.html`.
- Results and turnout: `results.php`, `function.php`, `views/results.view.html`.
- Location-scoped results: `results.php`, `api/get_constituencies.php`, `api/get_wards.php`, `includes/functions.php`.

### 4.4 Audit and Compliance
- Candidate change history: `admin_candidate_change_history.php`, `admin_records.php`, `function.php`.
- General action logging: audit log helpers in `function.php`.

## 5. Documentation Usage Notes
- Use this file as the primary grouped map for onboarding and maintenance.
- For function-level deep dives, start with `function.php`, then trace controller usage.
- Prefer grouped comments at block boundaries in source files instead of line-by-line comments.

## 6. Next Expansion (Optional)
- Add per-function `Input / Output / Side Effects` mini-specs for each PHP controller.
- Add sequence diagrams for login, vote submission, and result-filter workflows.
- Add data dictionary for key DB tables (`voters`, `candidates`, `votes`, `by_elections`, `audit_logs`).
