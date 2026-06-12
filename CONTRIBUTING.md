# Contributing to KernelEye

Thank you for your interest in contributing to KernelEye. This document
outlines the contribution workflow, coding standards, and legal requirements.

## Reporting Issues

### Bug Reports

Open a GitHub issue with:

- Affected component and version (`agent/VERSION` or `backend/VERSION`)
- Steps to reproduce
- Expected vs. actual behavior
- Relevant logs or environment details

### Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.** Follow the
process in [SECURITY.md](SECURITY.md) and report privately to
abdeljalil.aitetaleb@gmail.com.

## Contribution Workflow

1. **Fork** the repository on GitHub
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
   Branch naming: `feature/`, `fix/`, `docs/`, `chore/`
3. **Make your changes**, following the coding guidelines in
   [.agent/workflows/coding-guidelines.txt](.agent/workflows/coding-guidelines.txt)
4. **Write tests** for your changes when applicable
5. **Run existing tests** to verify nothing is broken:
   ```bash
   # Agent tests
   cd agent && go test ./...

   # Backend tests
   cd backend && go test ./...

   # Shared modules
   cd shared/scoring && go test ./...
   ```
6. **Commit with DCO sign-off** (see below)
7. **Push** your branch and open a pull request against `main`
8. **Respond to review** feedback

## Developer Certificate of Origin (DCO)

All commits must include a `Signed-off-by` line. This certifies that you
have the right to submit the contribution under the Apache-2.0 license.

Use the `-s` flag when committing:

```bash
git commit -s -m "Add XDP packet drop metrics"
```

This produces a commit message like:

```
Add XDP packet drop metrics

Signed-off-by: Your Name <your.email@example.com>
```

If you are using a Git tool that does not support the `-s` flag, add the
`Signed-off-by: Your Name <you@example.com>` line manually at the end of
your commit message. The name and email must match your Git identity.

By signing off your commits, you certify the following (from
[developercertificate.org](https://developercertificate.org/)):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## Pull Request Guidelines

- Each PR should address a single concern
- Keep changes focused and reasonably sized
- Reference related issues in the PR description
- Ensure CI passes before requesting review
- All PRs are reviewed by the project maintainer

## Coding Guidelines

See [.agent/workflows/coding-guidelines.txt](.agent/workflows/coding-guidelines.txt)
for the project's coding standards, including:

- File size limits (max ~200 lines per file)
- Go code conventions
- eBPF C code conventions
- TypeScript/React conventions

## Architecture

Before making significant changes, review the architecture documentation:

- [docs/architecture.md](docs/architecture.md)
- [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- [docs/TRUST_MODEL.md](docs/TRUST_MODEL.md)
- [docs/development.md](docs/development.md)

## License

By contributing, you agree that your contributions will be licensed under
the Apache License, Version 2.0, as described in [LICENSE](LICENSE).
