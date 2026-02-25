"""
Minimal reproduction of a Rootly Python SDK bug.

Bug:  AlertsSourceAlertSourceUrgencyRulesAttributesItem.from_dict() raises
      TypeError when the API returns conditionable_type=null for an urgency
      rule attached to an alert source.

SDK version: rootly>=1.1.0  (check with: pip show rootly)
Python:       3.x
Reported:     2026-02-25

Steps to reproduce
------------------
1. In the Rootly UI, create an alert source that has at least one urgency rule
   whose "conditionable_type" field is null/absent (the UI may leave this null
   when the rule is not yet fully configured).
2. Call GET /v1/alert_sources via the SDK.

The SDK's generated check function only accepts the literal string "AlertField"
for that field; it raises TypeError on None even though the JSON:API spec allows
null values for nullable attributes.

Expected behaviour: null conditionable_type should be treated as absent/unset.
Actual behaviour:   TypeError is raised, aborting the entire list call.
"""

import os
import sys

from rootly_sdk import AuthenticatedClient
from rootly_sdk.api.alert_sources import list_alerts_sources
from rootly_sdk.models.alerts_source_alert_source_urgency_rules_attributes_item import (
    AlertsSourceAlertSourceUrgencyRulesAttributesItem,
)

# ---------------------------------------------------------------------------
# Reproduce via the SDK model directly (no network call required)
# ---------------------------------------------------------------------------

print("=== Part 1: Model-level reproduction (no API key needed) ===\n")

# The API legitimately returns a payload like this for an urgency rule whose
# conditionable_type has not been set:
urgency_rule_with_null_conditionable_type = {
    "json_path": "$.severity",
    "operator": "is",             # valid SDK operator value
    "value": "critical",
    "conditionable_type": None,   # <-- null in the API JSON response
    "conditionable_id": None,
    "kind": "payload",            # valid SDK kind value
    "alert_urgency_id": "some-uuid",
}

print("Calling AlertsSourceAlertSourceUrgencyRulesAttributesItem.from_dict()")
print("with conditionable_type=None ...\n")

try:
    item = AlertsSourceAlertSourceUrgencyRulesAttributesItem.from_dict(
        urgency_rule_with_null_conditionable_type
    )
    print("SUCCESS (unexpected — bug may be fixed in this SDK version)")
except TypeError as exc:
    print(f"TypeError raised (bug confirmed):\n  {exc}\n")
    print(
        "Root cause: check_alerts_source_alert_source_urgency_rules_attributes_item_"
        "conditionable_type() only accepts 'AlertField'; it does not handle None.\n"
        "File: rootly_sdk/models/"
        "alerts_source_alert_source_urgency_rules_attributes_item_conditionable_type.py"
    )

# ---------------------------------------------------------------------------
# Reproduce via a live API call (requires ROOTLY_API_KEY in environment)
# ---------------------------------------------------------------------------

print("\n=== Part 2: Live API reproduction (requires ROOTLY_API_KEY) ===\n")

api_key = os.environ.get("ROOTLY_API_KEY")
if not api_key:
    print("ROOTLY_API_KEY not set — skipping live API test.")
    print("To run the live test:  ROOTLY_API_KEY=<key> python repro_sdk_bug.py")
    sys.exit(0)

client = AuthenticatedClient(base_url="https://api.rootly.com", token=api_key)

print("Calling GET /v1/alert_sources ...")
with client as c:
    try:
        response = list_alerts_sources.sync_detailed(client=c, pagesize=100)
        if response.status_code == 200 and response.parsed is not None:
            print(
                f"SUCCESS — fetched {len(response.parsed.data)} alert source(s).\n"
                "None of the alert sources on this account have null conditionable_type\n"
                "in their urgency rules, so the bug was not triggered.\n"
                "To trigger it, create an alert source with a partially-configured\n"
                "urgency rule so that conditionable_type is left null."
            )
        else:
            print(f"Unexpected status: {response.status_code}")
    except TypeError as exc:
        print(f"TypeError raised during SDK response parsing (bug confirmed):\n  {exc}")
