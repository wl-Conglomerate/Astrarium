<!--
PR TITLE: write a short, meaningful summary of the change as a whole, in the
imperative mood - don't leave the auto-filled first-commit message. Examples:
  * Add canary rollout to the deploy command
  * Improve CI/CD caching and test matrix
  * Fix recipient removal for pgp-only sops rules
Individual commits should still follow Conventional Commits (see CONTRIBUTING.md);
on merge/rebase those commits drive the release changelog.
-->

## Type of change

<!-- Please check all that apply - this drives the PR's type labels. -->

- [ ] **Bug fix** (fixes an issue in rendering or CLI behaviour)
- [ ] **Feature** (adds new deployment capability or CLI command)
- [ ] **Enhancement** (improves existing rendering logic or output)
- [ ] **Refactor** (restructures code without changing behaviour)
- [ ] **Breaking change** (changes existing configs, CLI usage, or rendered output)
- [ ] **Security** (security-related fix or hardening)

## Description

### Why is this change needed?

<!-- Explain the motivation and context for this change -->

### Related Issues

<!-- Link to related issues using "Fixes #123", "Closes #123", or "Relates to #123" -->

## Testing

<!-- Describe how you tested your changes -->

- [ ] Tested against a sample deployment repo
- [ ] Verified rendered configs are valid
- [ ] No testing required (documentation changes only)

## Checklist

<!-- Ensure all applicable items are completed before requesting review -->

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Linter and type checker pass (`uv run poe check`)
- [ ] Documentation updated (if applicable)
