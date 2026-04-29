import argparse
import importlib.util
import json
import os
import pprint
import re

from rootly_sdk import AuthenticatedClient
from rootly_sdk.api.services import create_service, list_services, update_service
from rootly_sdk.api.roles import create_role, list_roles, update_role
from rootly_sdk.api.teams import create_team, list_teams, update_team
from rootly_sdk.api.alert_sources import create_alerts_source, list_alerts_sources, update_alerts_source
from rootly_sdk.api.alert_routes import create_alert_route, list_alert_routes, update_alert_route
from rootly_sdk.api.escalation_policies import (
    create_escalation_policy,
    list_escalation_policies,
    update_escalation_policy,
)
from rootly_sdk.models.new_service import NewService
from rootly_sdk.models.new_role import NewRole
from rootly_sdk.models.new_team import NewTeam
from rootly_sdk.models.update_service import UpdateService
from rootly_sdk.models.update_role import UpdateRole
from rootly_sdk.models.update_team import UpdateTeam
from rootly_sdk.models.new_alerts_source import NewAlertsSource
from rootly_sdk.models.update_alerts_source import UpdateAlertsSource
from rootly_sdk.models.new_alert_route import NewAlertRoute
from rootly_sdk.models.update_alert_route import UpdateAlertRoute
from rootly_sdk.models.new_escalation_policy import NewEscalationPolicy
from rootly_sdk.models.update_escalation_policy import UpdateEscalationPolicy
from rootly_sdk.types import UNSET

DATA_FILE = os.path.join(os.path.dirname(__file__), "data.py")

# Writable service fields that are readable from the Service response model.
# Excludes read-only fields (created_at, updated_at, slug, alerts_email_address)
# and fields present in NewServiceDataAttributes but absent from Service
# (opsgenie_team_id, show_uptime, show_uptime_last_days).
_SERVICE_SIMPLE_WRITABLE = [
    "name", "description", "public_description", "notify_emails", "color", "position",
    "backstage_id", "pagerduty_id", "external_id", "opsgenie_id", "cortex_id",
    "service_now_ci_sys_id", "github_repository_name", "github_repository_branch",
    "gitlab_repository_name", "gitlab_repository_branch", "environment_ids",
    "service_ids", "owner_group_ids", "owner_user_ids", "kubernetes_deployment_name",
    "alerts_email_enabled", "alert_urgency_id", "escalation_policy_id",
    "alert_broadcast_enabled", "incident_broadcast_enabled",
]

# Writable team fields that are readable from the Team response model.
# Excludes read-only fields (created_at, updated_at, slug, alerts_email_address)
# and opsgenie_team_id (create-only, absent from Team response and UpdateTeamDataAttributes).
_TEAM_SIMPLE_WRITABLE = [
    "name", "description", "notify_emails", "color", "position",
    "backstage_id", "external_id", "pagerduty_id", "pagerduty_service_id",
    "opsgenie_id", "victor_ops_id", "pagertree_id", "cortex_id",
    "service_now_ci_sys_id", "user_ids", "admin_ids",
    "alerts_email_enabled", "alert_urgency_id",
    "alert_broadcast_enabled", "incident_broadcast_enabled",
    "auto_add_members_when_attached",
]

# Alert source fields that exist only in the response (server-generated); strip on export.
_ALERT_SOURCE_READ_ONLY = {"status", "secret", "created_at", "updated_at", "email", "webhook_endpoint"}

# Writable fields for nested alert source sub-resources.
_URGENCY_RULE_WRITABLE = {"json_path", "operator", "value", "conditionable_type", "conditionable_id", "kind", "alert_urgency_id"}
_ALERT_FIELD_WRITABLE = {"alert_field_id", "template_body"}
_ALERT_TEMPLATE_WRITABLE = {"title", "description", "external_url"}

# Escalation policy fields that exist only in the response; strip on export.
_ESCALATION_POLICY_READ_ONLY = {"created_by_user_id", "last_updated_by_user_id", "created_at", "updated_at"}

# All writable permission list fields on roles.
_ROLE_PERMISSION_FIELDS = [
    "alerts_permissions", "api_keys_permissions", "audits_permissions",
    "billing_permissions", "environments_permissions", "form_fields_permissions",
    "functionalities_permissions", "groups_permissions", "incident_causes_permissions",
    "incident_feedbacks_permissions", "incident_roles_permissions", "incident_types_permissions",
    "incidents_permissions", "integrations_permissions", "invitations_permissions",
    "playbooks_permissions", "private_incidents_permissions", "pulses_permissions",
    "retrospective_permissions", "roles_permissions", "secrets_permissions",
    "services_permissions", "severities_permissions", "status_pages_permissions",
    "webhooks_permissions", "workflows_permissions",
]


# --- Pagination helpers ---

def fetch_all_services(client: AuthenticatedClient) -> list:
    """Fetch every service from Rootly, handling pagination."""
    items = []
    page = 1
    while True:
        response = list_services.sync_detailed(client=client, pagenumber=page, pagesize=100)
        if response.status_code != 200 or response.parsed is None:
            print(f"Error fetching services (page {page}): {response.status_code}")
            break
        items.extend(response.parsed.data)
        if response.parsed.links.next_ is None:
            break
        page += 1
    return items


def fetch_all_roles(client: AuthenticatedClient) -> list:
    """Fetch every role from Rootly, handling pagination."""
    items = []
    page = 1
    while True:
        response = list_roles.sync_detailed(client=client, pagenumber=page, pagesize=100)
        if response.status_code != 200 or response.parsed is None:
            print(f"Error fetching roles (page {page}): {response.status_code}")
            break
        items.extend(response.parsed.data)
        if response.parsed.links.next_ is None:
            break
        page += 1
    return items


def fetch_all_teams(client: AuthenticatedClient) -> list:
    """Fetch every team from Rootly, handling pagination."""
    items = []
    page = 1
    while True:
        response = list_teams.sync_detailed(client=client, pagenumber=page, pagesize=100)
        if response.status_code != 200 or response.parsed is None:
            print(f"Error fetching teams (page {page}): {response.status_code}")
            break
        items.extend(response.parsed.data)
        if response.parsed.links.next_ is None:
            break
        page += 1
    return items


def fetch_all_alert_sources(client: AuthenticatedClient) -> list:
    """Fetch every alert source from Rootly, handling pagination."""
    items = []
    page = 1
    while True:
        response = list_alerts_sources.sync_detailed(client=client, pagenumber=page, pagesize=100)
        if response.status_code != 200 or response.parsed is None:
            print(f"Error fetching alert sources (page {page}): {response.status_code}")
            break
        items.extend(response.parsed.data)
        if response.parsed.links.next_ is None:
            break
        page += 1
    return items


def fetch_all_alert_routes(client: AuthenticatedClient) -> list:
    """Fetch every alert route from Rootly, handling pagination."""
    items = []
    page = 1
    while True:
        response = list_alert_routes.sync_detailed(client=client, pagenumber=page, pagesize=100)
        if response.status_code != 200 or response.parsed is None:
            print(f"Error fetching alert routes (page {page}): {response.status_code}")
            break
        items.extend(response.parsed.data)
        if response.parsed.links.next_ is None:
            break
        page += 1
    return items


def fetch_all_escalation_policies(client: AuthenticatedClient) -> list:
    """Fetch every escalation policy from Rootly, handling pagination."""
    items = []
    page = 1
    while True:
        response = list_escalation_policies.sync_detailed(client=client, pagenumber=page, pagesize=100)
        if response.status_code != 200 or response.parsed is None:
            print(f"Error fetching escalation policies (page {page}): {response.status_code}")
            break
        items.extend(response.parsed.data)
        if response.parsed.links.next_ is None:
            break
        page += 1
    return items


# --- Conversion helpers ---

def service_to_writable_dict(item) -> dict:
    """Extract only writable attributes from a ServiceListDataItem."""
    attrs = item.attributes
    d = {}

    for field in _SERVICE_SIMPLE_WRITABLE:
        val = getattr(attrs, field)
        if val is not UNSET and val is not None:
            d[field] = val

    # Complex fields whose values are SDK objects that need serialization.
    if attrs.slack_channels is not UNSET and attrs.slack_channels is not None:
        d["slack_channels"] = [ch.to_dict() for ch in attrs.slack_channels]
    if attrs.slack_aliases is not UNSET and attrs.slack_aliases is not None:
        d["slack_aliases"] = [a.to_dict() for a in attrs.slack_aliases]
    if attrs.alert_broadcast_channel is not UNSET and attrs.alert_broadcast_channel is not None:
        d["alert_broadcast_channel"] = attrs.alert_broadcast_channel.to_dict()
    if attrs.incident_broadcast_channel is not UNSET and attrs.incident_broadcast_channel is not None:
        d["incident_broadcast_channel"] = attrs.incident_broadcast_channel.to_dict()

    return d


def role_to_writable_dict(item) -> dict:
    """Extract only writable attributes from a RoleListDataItem."""
    attrs = item.attributes
    # name and slug are always present on a Role response.
    d = {"name": attrs.name, "slug": attrs.slug}

    if attrs.incident_permission_set_id is not UNSET and attrs.incident_permission_set_id is not None:
        d["incident_permission_set_id"] = attrs.incident_permission_set_id

    for field in _ROLE_PERMISSION_FIELDS:
        val = getattr(attrs, field)
        # val is a list (possibly empty); only include if non-empty.
        if val is not UNSET and len(val) > 0:
            d[field] = list(val)

    return d


def team_to_writable_dict(item) -> dict:
    """Extract only writable attributes from a TeamListDataItem."""
    attrs = item.attributes
    d = {}

    for field in _TEAM_SIMPLE_WRITABLE:
        val = getattr(attrs, field)
        if val is not UNSET and val is not None:
            d[field] = val

    # Complex fields whose values are SDK objects that need serialization.
    if attrs.slack_channels is not UNSET and attrs.slack_channels is not None:
        d["slack_channels"] = [ch.to_dict() for ch in attrs.slack_channels]
    if attrs.slack_aliases is not UNSET and attrs.slack_aliases is not None:
        d["slack_aliases"] = [a.to_dict() for a in attrs.slack_aliases]
    if attrs.alert_broadcast_channel is not UNSET and attrs.alert_broadcast_channel is not None:
        d["alert_broadcast_channel"] = attrs.alert_broadcast_channel.to_dict()
    if attrs.incident_broadcast_channel is not UNSET and attrs.incident_broadcast_channel is not None:
        d["incident_broadcast_channel"] = attrs.incident_broadcast_channel.to_dict()

    return d


def alert_source_to_writable_dict(item) -> dict:
    """Extract only writable attributes from an AlertsSourceListDataItem.

    Calls the SDK's own to_dict() for correct serialization (e.g. enum → str),
    then strips server-generated read-only keys (top-level and nested).
    """
    d = item.attributes.to_dict()
    for key in _ALERT_SOURCE_READ_ONLY:
        d.pop(key, None)
    # Strip read-only and None fields from urgency rule items.
    if d.get("alert_source_urgency_rules_attributes"):
        d["alert_source_urgency_rules_attributes"] = [
            {k: v for k, v in rule.items() if k in _URGENCY_RULE_WRITABLE and v is not None}
            for rule in d["alert_source_urgency_rules_attributes"]
        ]
    # Strip read-only fields from alert field items (keep only alert_field_id + template_body).
    if d.get("alert_source_fields_attributes"):
        d["alert_source_fields_attributes"] = [
            {k: v for k, v in field.items() if k in _ALERT_FIELD_WRITABLE}
            for field in d["alert_source_fields_attributes"]
        ]
    # Strip read-only fields from alert template (keep only title, description, external_url).
    if d.get("alert_template_attributes") and isinstance(d["alert_template_attributes"], dict):
        d["alert_template_attributes"] = {
            k: v for k, v in d["alert_template_attributes"].items()
            if k in _ALERT_TEMPLATE_WRITABLE
        }
    return d


def alert_route_to_writable_dict(item) -> dict:
    """Extract all attributes from an AlertRouteListDataItem.

    AlertRoute has no server-generated read-only fields; to_dict() handles
    UUID → str serialization for alerts_source_ids and owning_team_ids.
    """
    return item.attributes.to_dict()


def escalation_policy_to_writable_dict(item) -> dict:
    """Extract only writable attributes from an EscalationPolicyListDataItem.

    Calls the SDK's own to_dict() for correct serialization (business_hours),
    then strips server-generated read-only keys.
    """
    d = item.attributes.to_dict()
    for key in _ESCALATION_POLICY_READ_ONLY:
        d.pop(key, None)
    return d


# --- Report field specs ---
#
# Each entry is a (label, extractor_fn) tuple where:
#   extractor_fn(item, context) -> str
#
# 'context' is a dict with:
#   "id_to_name": dict[str, str]  - maps service id -> service name
#
# The first field in each list is printed as the item heading (no label/indent).
# All subsequent fields are printed indented with aligned labels.
# To add a new field, append a tuple here.

def _resolve_service_names(ids, id_to_name: dict) -> str:
    if not ids or ids is UNSET:
        return "(none)"
    return ", ".join(id_to_name.get(sid, sid) for sid in ids)


SERVICE_REPORT_FIELDS = [
    ("Name",         lambda item, ctx: item.attributes.name),
    ("ID",           lambda item, ctx: item.id),
    ("Dependencies", lambda item, ctx: _resolve_service_names(
        item.attributes.service_ids
        if item.attributes.service_ids not in (None, UNSET)
        else [],
        ctx["id_to_name"],
    )),
]

ROLE_REPORT_FIELDS = [
    ("Name", lambda item, ctx: item.attributes.name),
    ("Slug", lambda item, ctx: item.attributes.slug),
]

TEAM_REPORT_FIELDS = [
    ("Name", lambda item, ctx: item.attributes.name),
    ("Slug", lambda item, ctx: item.attributes.slug),
]

ALERT_SOURCE_REPORT_FIELDS = [
    ("Name",        lambda item, ctx: item.attributes.name),
    ("ID",          lambda item, ctx: item.id),
    ("Source Type", lambda item, ctx: item.attributes.source_type if item.attributes.source_type is not UNSET else "(none)"),
    ("Status",      lambda item, ctx: item.attributes.status),
]

ALERT_ROUTE_REPORT_FIELDS = [
    ("Name",    lambda item, ctx: item.attributes.name),
    ("ID",      lambda item, ctx: item.id),
    ("Enabled", lambda item, ctx: item.attributes.enabled if item.attributes.enabled is not UNSET else "(unset)"),
    ("Sources", lambda item, ctx: ", ".join(str(sid) for sid in item.attributes.alerts_source_ids)
                                  if item.attributes.alerts_source_ids else "(none)"),
]

ESCALATION_POLICY_REPORT_FIELDS = [
    ("Name",         lambda item, ctx: item.attributes.name),
    ("ID",           lambda item, ctx: item.id),
    ("Repeat Count", lambda item, ctx: item.attributes.repeat_count),
    ("Description",  lambda item, ctx: item.attributes.description
                                       if item.attributes.description not in (None, UNSET) else "(none)"),
]


def _print_section(title: str, items: list, fields: list, context: dict) -> None:
    """Print one report section with aligned labels."""
    label_width = max((len(label) for label, _ in fields[1:]), default=0)
    heading_fn = fields[0][1]
    print(f"\n{title} ({len(items)})")
    print("=" * 60)
    for item in items:
        print(heading_fn(item, context))
        for label, extractor in fields[1:]:
            print(f"  {label:<{label_width}}: {extractor(item, context)}")
        print()


def print_report(client: AuthenticatedClient) -> None:
    """Print a human-readable report of all resources."""
    print("Fetching all services...")
    service_items = fetch_all_services(client)
    print("Fetching all roles...")
    role_items = fetch_all_roles(client)
    print("Fetching all teams...")
    team_items = fetch_all_teams(client)
    print("Fetching all alert sources...")
    alert_source_items = fetch_all_alert_sources(client)
    print("Fetching all alert routes...")
    alert_route_items = fetch_all_alert_routes(client)
    print("Fetching all escalation policies...")
    escalation_policy_items = fetch_all_escalation_policies(client)

    id_to_name = {item.id: item.attributes.name for item in service_items}
    context = {"id_to_name": id_to_name}

    _print_section("Services", service_items, SERVICE_REPORT_FIELDS, context)
    _print_section("Roles", role_items, ROLE_REPORT_FIELDS, context)
    _print_section("Teams", team_items, TEAM_REPORT_FIELDS, context)
    _print_section("Alert Sources", alert_source_items, ALERT_SOURCE_REPORT_FIELDS, context)
    _print_section("Alert Routes", alert_route_items, ALERT_ROUTE_REPORT_FIELDS, context)
    _print_section("Escalation Policies", escalation_policy_items, ESCALATION_POLICY_REPORT_FIELDS, context)


# --- Export ---

def export_to_data_file(client: AuthenticatedClient) -> None:
    """Fetch all resources from Rootly and overwrite data.py."""
    print("Fetching all services...")
    service_items = fetch_all_services(client)
    services = [service_to_writable_dict(s) for s in service_items]
    print(f"  Fetched {len(services)} services.")

    print("Fetching all roles...")
    role_items = fetch_all_roles(client)
    roles = [role_to_writable_dict(r) for r in role_items]
    print(f"  Fetched {len(roles)} roles.")

    print("Fetching all teams...")
    team_items = fetch_all_teams(client)
    teams = [team_to_writable_dict(t) for t in team_items]
    print(f"  Fetched {len(teams)} teams.")

    print("Fetching all alert sources...")
    alert_source_items = fetch_all_alert_sources(client)
    alert_sources = [alert_source_to_writable_dict(s) for s in alert_source_items]
    print(f"  Fetched {len(alert_sources)} alert sources.")

    print("Fetching all alert routes...")
    alert_route_items = fetch_all_alert_routes(client)
    alert_routes = [alert_route_to_writable_dict(r) for r in alert_route_items]
    print(f"  Fetched {len(alert_routes)} alert routes.")

    print("Fetching all escalation policies...")
    escalation_policy_items = fetch_all_escalation_policies(client)
    escalation_policies = [escalation_policy_to_writable_dict(p) for p in escalation_policy_items]
    print(f"  Fetched {len(escalation_policies)} escalation policies.")

    def fmt(obj):
        return pprint.pformat(obj, indent=4, sort_dicts=False)

    content = (
        f"SERVICES = {fmt(services)}\n\n"
        f"ROLES = {fmt(roles)}\n\n"
        f"TEAMS = {fmt(teams)}\n\n"
        f"ALERT_SOURCES = {fmt(alert_sources)}\n\n"
        f"ALERT_ROUTES = {fmt(alert_routes)}\n\n"
        f"ESCALATION_POLICIES = {fmt(escalation_policies)}\n"
    )

    with open(DATA_FILE, "w") as f:
        f.write(content)

    print(
        f"\nWrote {len(services)} services, {len(roles)} roles, {len(teams)} teams, "
        f"{len(alert_sources)} alert sources, {len(alert_routes)} alert routes, and "
        f"{len(escalation_policies)} escalation policies to {DATA_FILE}"
    )


# --- Find helpers (used by ensure functions) ---

def find_existing_service(client: AuthenticatedClient, name: str) -> str | None:
    """Find a service by name and return its id, or None if not found."""
    response = list_services.sync_detailed(client=client, filtername=name)
    if response.status_code != 200 or response.parsed is None:
        return None
    for svc in response.parsed.data:
        if svc.attributes.name == name:
            return svc.id
    return None


def find_existing_role(client: AuthenticatedClient, name: str) -> str | None:
    """Find a role by name and return its id, or None if not found."""
    response = list_roles.sync_detailed(client=client, filtername=name)
    if response.status_code != 200 or response.parsed is None:
        return None
    for r in response.parsed.data:
        if r.attributes.name == name:
            return r.id
    return None


def find_existing_team(client: AuthenticatedClient, name: str) -> str | None:
    """Find a team by name and return its id, or None if not found."""
    response = list_teams.sync_detailed(client=client, filtername=name)
    if response.status_code != 200 or response.parsed is None:
        return None
    for t in response.parsed.data:
        if t.attributes.name == name:
            return t.id
    return None


def find_existing_alert_source(client: AuthenticatedClient, name: str) -> str | None:
    """Find an alert source by name and return its id, or None if not found."""
    response = list_alerts_sources.sync_detailed(client=client, filtername=name)
    if response.status_code != 200 or response.parsed is None:
        return None
    for s in response.parsed.data:
        if s.attributes.name == name:
            return s.id
    return None


def find_existing_alert_route(client: AuthenticatedClient, name: str) -> str | None:
    """Find an alert route by name and return its id, or None if not found."""
    response = list_alert_routes.sync_detailed(client=client, filtername=name)
    if response.status_code != 200 or response.parsed is None:
        return None
    for r in response.parsed.data:
        if r.attributes.name == name:
            return r.id
    return None


def find_existing_escalation_policy(client: AuthenticatedClient, name: str) -> str | None:
    """Find an escalation policy by name and return its id, or None if not found."""
    response = list_escalation_policies.sync_detailed(client=client, filtername=name)
    if response.status_code != 200 or response.parsed is None:
        return None
    for p in response.parsed.data:
        if p.attributes.name == name:
            return p.id
    return None


# --- Ensure (idempotent create/update) ---

def ensure_service(client: AuthenticatedClient, service_dict: dict) -> None:
    """Create a service if it doesn't exist, or update it if it does."""
    name = service_dict["name"]
    existing_id = find_existing_service(client, name)

    if existing_id is not None:
        payload = UpdateService.from_dict({
            "data": {
                "type": "services",
                "attributes": service_dict,
            }
        })
        response = update_service.sync_detailed(
            existing_id, client=client, body=payload
        )
        if response.status_code == 200:
            print(f"Updated service: {name} (id: {existing_id})")
        else:
            print(f"Failed to update service '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")
    else:
        payload = NewService.from_dict({
            "data": {
                "type": "services",
                "attributes": service_dict,
            }
        })
        response = create_service.sync_detailed(client=client, body=payload)
        if response.status_code == 201:
            result = response.parsed
            print(f"Created service: {name} (id: {result.data.id})")
        else:
            print(f"Failed to create service '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")


def ensure_role(client: AuthenticatedClient, role_dict: dict) -> None:
    """Create a role if it doesn't exist, or update it if it does."""
    name = role_dict["name"]
    if not name or name == "None":
        # Some built-in roles (e.g. no_access) have a null name in the API; skip them.
        return
    existing_id = find_existing_role(client, name)

    if existing_id is not None:
        payload = UpdateRole.from_dict({
            "data": {
                "type": "roles",
                "attributes": role_dict,
            }
        })
        response = update_role.sync_detailed(
            existing_id, client=client, body=payload
        )
        if response.status_code == 200:
            print(f"Updated role: {name} (id: {existing_id})")
        elif response.status_code == 404:
            # Built-in system roles (owner, admin, observer) return 404; they can't be modified.
            print(f"Skipping role '{name}': not modifiable (system role).")
        else:
            print(f"Failed to update role '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")
    else:
        payload = NewRole.from_dict({
            "data": {
                "type": "roles",
                "attributes": role_dict,
            }
        })
        response = create_role.sync_detailed(client=client, body=payload)
        if response.status_code == 201:
            result = response.parsed
            print(f"Created role: {name} (id: {result.data.id})")
        else:
            print(f"Failed to create role '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")


def ensure_team(client: AuthenticatedClient, team_dict: dict) -> None:
    """Create a team if it doesn't exist, or update it if it does."""
    name = team_dict["name"]
    existing_id = find_existing_team(client, name)

    if existing_id is not None:
        payload = UpdateTeam.from_dict({
            "data": {
                "type": "groups",
                "attributes": team_dict,
            }
        })
        response = update_team.sync_detailed(
            existing_id, client=client, body=payload
        )
        if response.status_code == 200:
            print(f"Updated team: {name} (id: {existing_id})")
        else:
            print(f"Failed to update team '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")
    else:
        payload = NewTeam.from_dict({
            "data": {
                "type": "groups",
                "attributes": team_dict,
            }
        })
        response = create_team.sync_detailed(client=client, body=payload)
        if response.status_code == 201:
            result = response.parsed
            print(f"Created team: {name} (id: {result.data.id})")
        else:
            print(f"Failed to create team '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")


def ensure_alert_source(client: AuthenticatedClient, alert_source_dict: dict) -> None:
    """Create an alert source if it doesn't exist, or update it if it does."""
    name = alert_source_dict["name"]
    existing_id = find_existing_alert_source(client, name)

    if existing_id is not None:
        payload = UpdateAlertsSource.from_dict({
            "data": {
                "type": "alert_sources",
                "attributes": alert_source_dict,
            }
        })
        response = update_alerts_source.sync_detailed(
            existing_id, client=client, body=payload
        )
        if response.status_code == 200:
            print(f"Updated alert source: {name} (id: {existing_id})")
        else:
            print(f"Failed to update alert source '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")
    else:
        payload = NewAlertsSource.from_dict({
            "data": {
                "type": "alert_sources",
                "attributes": alert_source_dict,
            }
        })
        response = create_alerts_source.sync_detailed(client=client, body=payload)
        if response.status_code == 201:
            result = response.parsed
            print(f"Created alert source: {name} (id: {result.data.id})")
        else:
            print(f"Failed to create alert source '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")


def ensure_alert_route(client: AuthenticatedClient, alert_route_dict: dict) -> None:
    """Create an alert route if it doesn't exist, or update it if it does."""
    name = alert_route_dict["name"]
    existing_id = find_existing_alert_route(client, name)

    if existing_id is not None:
        payload = UpdateAlertRoute.from_dict({
            "data": {
                "type": "alert_routes",
                "attributes": alert_route_dict,
            }
        })
        response = update_alert_route.sync_detailed(
            existing_id, client=client, body=payload
        )
        if response.status_code == 200:
            print(f"Updated alert route: {name} (id: {existing_id})")
        else:
            print(f"Failed to update alert route '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")
    else:
        payload = NewAlertRoute.from_dict({
            "data": {
                "type": "alert_routes",
                "attributes": alert_route_dict,
            }
        })
        response = create_alert_route.sync_detailed(client=client, body=payload)
        if response.status_code == 201:
            result = response.parsed
            print(f"Created alert route: {name} (id: {result.data.id})")
        else:
            print(f"Failed to create alert route '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")


def ensure_escalation_policy(client: AuthenticatedClient, policy_dict: dict) -> None:
    """Create an escalation policy if it doesn't exist, or update it if it does."""
    name = policy_dict["name"]
    existing_id = find_existing_escalation_policy(client, name)

    if existing_id is not None:
        payload = UpdateEscalationPolicy.from_dict({
            "data": {
                "type": "escalation_policies",
                "attributes": policy_dict,
            }
        })
        response = update_escalation_policy.sync_detailed(
            existing_id, client=client, body=payload
        )
        if response.status_code == 200:
            print(f"Updated escalation policy: {name} (id: {existing_id})")
        else:
            print(f"Failed to update escalation policy '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")
    else:
        payload = NewEscalationPolicy.from_dict({
            "data": {
                "type": "escalation_policies",
                "attributes": policy_dict,
            }
        })
        response = create_escalation_policy.sync_detailed(client=client, body=payload)
        if response.status_code == 201:
            result = response.parsed
            print(f"Created escalation policy: {name} (id: {result.data.id})")
        else:
            print(f"Failed to create escalation policy '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")


# --- Import ---

def load_data_file(path: str) -> tuple[list, list, list, list, list, list]:
    """Dynamically load all resource lists from a Python data file."""
    abs_path = os.path.abspath(path)
    spec = importlib.util.spec_from_file_location("_rootly_data", abs_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    teams = getattr(module, "TEAMS", [])
    alert_sources = getattr(module, "ALERT_SOURCES", [])
    alert_routes = getattr(module, "ALERT_ROUTES", [])
    escalation_policies = getattr(module, "ESCALATION_POLICIES", [])
    return module.SERVICES, module.ROLES, teams, alert_sources, alert_routes, escalation_policies


def run_import(client: AuthenticatedClient, path: str) -> None:
    """Load definitions from a file and ensure them in Rootly."""
    services, roles, teams, alert_sources, alert_routes, escalation_policies = load_data_file(path)
    print(
        f"Loaded {len(services)} services, {len(roles)} roles, {len(teams)} teams, "
        f"{len(alert_sources)} alert sources, {len(alert_routes)} alert routes, and "
        f"{len(escalation_policies)} escalation policies from {path}"
    )

    print("\nEnsuring services...")
    for service_dict in services:
        ensure_service(client, service_dict)

    print("\nEnsuring roles...")
    for role_dict in roles:
        ensure_role(client, role_dict)

    print("\nEnsuring teams...")
    for team_dict in teams:
        ensure_team(client, team_dict)

    print("\nEnsuring alert sources...")
    for alert_source_dict in alert_sources:
        ensure_alert_source(client, alert_source_dict)

    print("\nEnsuring alert routes...")
    for alert_route_dict in alert_routes:
        ensure_alert_route(client, alert_route_dict)

    print("\nEnsuring escalation policies...")
    for policy_dict in escalation_policies:
        ensure_escalation_policy(client, policy_dict)


# --- Pulumi import export ---

# Maps each resource kind to its Pulumi provider type string.
_PULUMI_TYPE = {
    "alert_source":       "rootly:index/alertsSource:AlertsSource",
    "alert_route":        "rootly:index/alertRoute:AlertRoute",
    "service":            "rootly:index/service:Service",
    "role":               "rootly:index/role:Role",
    "team":               "rootly:index/team:Team",
    "escalation_policy":  "rootly:index/escalationPolicy:EscalationPolicy",
}


def _slugify(name: str) -> str:
    """Convert a display name to a valid Pulumi resource name (lowercase, hyphens)."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    # Resource names must start with a letter.
    if slug and slug[0].isdigit():
        slug = "r-" + slug
    return slug or "unnamed"


def _build_import_entries(kind: str, items: list) -> list[dict]:
    """Return a list of Pulumi import entries for a collection of Rootly items."""
    pulumi_type = _PULUMI_TYPE[kind]
    entries = []
    seen_names: dict[str, int] = {}
    for item in items:
        display_name = getattr(item.attributes, "name", None) or str(item.id)
        base_slug = _slugify(str(display_name))
        # De-duplicate slugs within the same resource type.
        count = seen_names.get(base_slug, 0)
        seen_names[base_slug] = count + 1
        slug = base_slug if count == 0 else f"{base_slug}-{count}"
        entries.append({
            "type": pulumi_type,
            "name": slug,
            "id": str(item.id),
            # logicalName preserves the original display name as a comment in generated code.
            "logicalName": display_name,
        })
    return entries


def export_pulumi_imports(client: AuthenticatedClient, output_path: str) -> None:
    """Fetch all Rootly resources and write a Pulumi bulk-import JSON file.

    This function is strictly read-only — it calls only list/get endpoints and
    does not create, update, or delete anything in Rootly or Pulumi.
    """
    print("Fetching resources from Rootly (read-only)...")

    print("  Fetching alert sources...")
    alert_source_items = fetch_all_alert_sources(client)
    print("  Fetching alert routes...")
    alert_route_items = fetch_all_alert_routes(client)
    print("  Fetching services...")
    service_items = fetch_all_services(client)
    print("  Fetching roles...")
    role_items = fetch_all_roles(client)
    print("  Fetching teams...")
    team_items = fetch_all_teams(client)
    print("  Fetching escalation policies...")
    escalation_policy_items = fetch_all_escalation_policies(client)

    resources = (
        _build_import_entries("alert_source", alert_source_items)
        + _build_import_entries("alert_route", alert_route_items)
        + _build_import_entries("service", service_items)
        + _build_import_entries("role", role_items)
        + _build_import_entries("team", team_items)
        + _build_import_entries("escalation_policy", escalation_policy_items)
    )

    import_doc = {"resources": resources}

    with open(output_path, "w") as f:
        json.dump(import_doc, f, indent=2)

    counts = {
        "alert_sources": len(alert_source_items),
        "alert_routes": len(alert_route_items),
        "services": len(service_items),
        "roles": len(role_items),
        "teams": len(team_items),
        "escalation_policies": len(escalation_policy_items),
    }
    total = sum(counts.values())
    print(f"\nWrote {total} import entries to {output_path}:")
    for kind, count in counts.items():
        print(f"  {kind}: {count}")
    print(
        f"\nTo import into Pulumi, run from your monitoring stack directory:\n"
        f"  pulumi import --file {os.path.abspath(output_path)} --generate-code"
    )


# --- Entry point ---

def main():
    parser = argparse.ArgumentParser(description="Manage Rootly services and roles")
    parser.add_argument(
        "--import",
        dest="import_file",
        nargs="?",
        const="data.py",
        default=None,
        metavar="FILE",
        help="Create/update services and roles from FILE (default: data.py)",
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Fetch all services and roles from Rootly and overwrite data.py",
    )
    parser.add_argument(
        "--pulumi-import",
        dest="pulumi_import_file",
        nargs="?",
        const="pulumi_imports.json",
        default=None,
        metavar="FILE",
        help=(
            "Fetch all Rootly resources and write a Pulumi bulk-import JSON file "
            "(default: pulumi_imports.json). Read-only — nothing is modified."
        ),
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print a report of all current services and roles",
    )
    args = parser.parse_args()

    if not (args.import_file or args.export or args.report or args.pulumi_import_file):
        parser.print_help()
        return

    api_key = os.environ.get("ROOTLY_API_KEY")
    if not api_key:
        print("Error: ROOTLY_API_KEY environment variable not set")
        return

    client = AuthenticatedClient(
        base_url="https://api.rootly.com",
        token=api_key,
    )

    with client as client:
        if args.import_file:
            run_import(client, args.import_file)
        elif args.export:
            export_to_data_file(client)
        elif args.pulumi_import_file:
            export_pulumi_imports(client, args.pulumi_import_file)
        elif args.report:
            print_report(client)


if __name__ == "__main__":
    main()
