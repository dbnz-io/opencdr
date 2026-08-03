# SIEM Integrations

OpenCDR alerts can be shipped to a SIEM using either the built-in custom webhook channel or the SNS fan-out pattern. The right choice depends on whether your SIEM accepts raw JSON over HTTP or requires a specific payload format.

| Approach | Best for |
|---|---|
| Custom webhook | Quick setup, SIEM accepts generic JSON HTTP ingest |
| SNS → Lambda | Production pipelines, payload transformation, proper field mapping |

## Datadog

**Option 1 — Custom webhook (quick start)**

Datadog's [Logs HTTP API](https://docs.datadoghq.com/api/latest/logs/) accepts JSON directly. No extra infrastructure needed.

```bash
python3 scripts/opencdr.py settings set \
  --webhook-url https://http-intake.logs.datadoghq.com/api/v2/logs \
  --webhook-name datadog \
  --webhook-header "DD-API-KEY=<your-datadog-api-key>" \
  --webhook-header "Content-Type=application/json"
```

Alerts land in Datadog Logs immediately. Use the `rule_id`, `severity`, and `actor` fields to build log-based monitors and dashboards.

> For EU accounts use `https://http-intake.logs.datadoghq.eu/api/v2/logs`.

**Option 2 — SNS → Datadog Forwarder Lambda (recommended for production)**

The [Datadog Forwarder](https://docs.datadoghq.com/logs/guide/forwarder/) is a Lambda maintained by Datadog that handles batching, tagging, retries, and proper log pipeline ingestion.

1. Deploy the Datadog Forwarder from the [AWS Serverless Application Repository](https://serverlessrepo.aws.amazon.com/applications/us-east-1/464622532012/Datadog-Forwarder)
2. Subscribe it to the OpenCDR alerts topic:

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:<region>:<account-id>:opencdr-<stage>-alerts \
  --protocol lambda \
  --notification-endpoint arn:aws:lambda:<region>:<account-id>:function:datadog-forwarder

aws lambda add-permission \
  --function-name datadog-forwarder \
  --statement-id opencdr-sns-invoke \
  --action lambda:InvokeFunction \
  --principal sns.amazonaws.com \
  --source-arn arn:aws:sns:<region>:<account-id>:opencdr-<stage>-alerts
```

Logs appear in Datadog under the `aws.lambda` source and can be re-indexed with a custom pipeline.

---

## Splunk

**Option 1 — SNS → Lambda with HEC wrapper (recommended)**

Splunk's [HTTP Event Collector (HEC)](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector) requires payloads wrapped as `{"event": <data>, "sourcetype": "..."}`. A small Lambda handles this:

1. Enable HEC in Splunk and generate a token
2. Deploy a Lambda that wraps and forwards the alert:

```python
import json, urllib.request

HEC_URL   = "https://<splunk-host>:8088/services/collector/event"
HEC_TOKEN = "<your-hec-token>"

def handler(event, context):
    for record in event["Records"]:
        alert = json.loads(record["Sns"]["Message"])
        payload = json.dumps({
            "event": alert,
            "sourcetype": "opencdr:alert",
            "index": "security",
        }).encode()
        req = urllib.request.Request(
            HEC_URL,
            data=payload,
            headers={
                "Authorization": f"Splunk {HEC_TOKEN}",
                "Content-Type": "application/json",
            },
        )
        urllib.request.urlopen(req, timeout=10)
```

3. Subscribe the Lambda to the alerts topic (same `sns subscribe` + `lambda add-permission` commands as above).

**Option 2 — Custom webhook (Splunk Cloud with HEC enabled)**

If your Splunk instance has HEC reachable over HTTPS and you handle the payload wrapper externally (e.g. a Splunk-managed endpoint), you can use the webhook channel directly:

```bash
python3 scripts/opencdr.py settings set \
  --webhook-url https://<splunk-host>:8088/services/collector/event \
  --webhook-name splunk \
  --webhook-header "Authorization=Splunk <hec-token>"
```

Note that Splunk HEC expects `{"event": ...}` — the raw alert JSON will be rejected without the wrapper. Use the Lambda approach above if you can't pre-wrap at the Splunk side.

---

## Other SIEMs

The same SNS → Lambda pattern works for any SIEM with an ingest API. Common examples:

| SIEM | Ingest mechanism | Notes |
|---|---|---|
| **Microsoft Sentinel** | [Data Collection Rule API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview) | Requires Azure AD token — use Lambda to handle OAuth |
| **Elastic / OpenSearch** | [Bulk API](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html) | POST `/_bulk` with index action wrapper |
| **Chronicle (Google)** | [Unified Data Model API](https://cloud.google.com/chronicle/docs/reference/udm-field-list) | Lambda handles GCP service account auth |
| **IBM QRadar** | Syslog or [REST API](https://www.ibm.com/docs/en/qradar-on-cloud) | Lambda formats as CEF or uses the log source API |
| **Sumo Logic** | [HTTP Source](https://help.sumologic.com/docs/send-data/hosted-collectors/http-source/) | Accepts raw JSON — custom webhook channel works directly |

For SIEMs that accept raw JSON over HTTPS (like Sumo Logic), the custom webhook channel is sufficient. For anything requiring payload transformation, authentication flows, or batching, use the SNS → Lambda pattern.
