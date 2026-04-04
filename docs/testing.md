# Testing

## Unit Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v

# With coverage
pytest tests/ --cov=src/domain --cov-report=term-missing
```

## Local Rule Testing

Test all rules against sample events without deploying to AWS:

```bash
python3 scripts/test_rules_local.py

# Filter by event
python3 scripts/test_rules_local.py --event 012

# Filter by rule
python3 scripts/test_rules_local.py --rule cloudtrail
```

Sample events for all 19 signal rules live in `support_files/test_events/`.

## Integration Testing (Deployed Stack)

```bash
# Test all events against the deployed processor Lambda
./scripts/test_deployed.sh

# Test a single event
./scripts/test_deployed.sh --event 009

# Test against prod
./scripts/test_deployed.sh --stage prod --region us-west-2
```
