## What does this PR do?

<!-- One paragraph describing the change and why it is needed -->

## Type of change

- [ ] Bug fix
- [ ] New detection rule
- [ ] New feature
- [ ] Infrastructure / deployment change
- [ ] Tests / tooling

## Checklist

- [ ] `pytest tests/ -v` passes locally
- [ ] New detection rules include a matching test event in `support_files/test_events/`
- [ ] No secrets, real account IDs, or real ARNs in committed files
- [ ] `serverless.yml` IAM changes follow least-privilege (scoped per function)
