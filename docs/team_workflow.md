# Team Workflow, Branch Discipline, and PR Rules

To maintain high code quality and prevent the team from breaking the core routing engine or user experience, all contributors must adhere to the following workflow.

## 1. Branching Strategy

- **No direct commits to `main`.**
- `main` must ALWAYS run the SatsPath demo flawlessly.
- All new work must be done on feature branches.
- Feature branches are merged into `develop` or experimental integration branches first.
- `develop` is merged into `main` ONLY when the demo is fully tested and verified.

**Branch Naming Convention:**

- `feature/<issue-name>` (e.g., `feature/lnurl-pay`)
- `fix/<issue-name>` (e.g., `fix/dust-threshold`)
- `docs/<issue-name>`

## 2. Pull Request (PR) Rules

- **One issue = one branch = one PR.** Keep scope tight.
- Do not mix protocol changes, frontend changes, and execution logic in the same PR.
- **No secrets in commits.** Never commit private keys, macaroons, or .env files.
- Mainnet execution code requires a mandatory Security Review before merging.

### PR Checklist

Before requesting a review, the author must ensure:

- [ ] Code compiles and tests pass (`cargo test --workspace`).
- [ ] The existing demo still works.
- [ ] New components do not introduce dangerous mainnet fallbacks.
- [ ] No fake invoices or plaintext secret storage were added.

## 3. Definition of Done

A task is considered "Done" when:

1. The acceptance criteria in the issue are fully met.
2. Unit tests or integration mocks cover the success and failure paths.
3. The PR is reviewed and approved by the respective module owner (e.g., Swap engine owner, Protocol Rust owner).
4. The code is merged into the target branch without breaking existing pipelines.
