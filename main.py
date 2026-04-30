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

# --- Additional SDK imports for Pulumi-import coverage ---
from rootly_sdk.api.environments import list_environments
from rootly_sdk.api.severities import list_severities
from rootly_sdk.api.functionalities import list_functionalities
from rootly_sdk.api.causes import list_causes
from rootly_sdk.api.incident_types import list_incident_types
from rootly_sdk.api.incident_roles import list_incident_roles
from rootly_sdk.api.incident_role_tasks import list_incident_role_tasks
from rootly_sdk.api.schedules import list_schedules
from rootly_sdk.api.schedule_rotations import list_schedule_rotations
from rootly_sdk.api.schedule_rotation_active_days import list_schedule_rotation_active_days
from rootly_sdk.api.schedule_rotation_users import list_schedule_rotation_users
from rootly_sdk.api.playbooks import list_playbooks
from rootly_sdk.api.playbook_tasks import list_playbook_tasks
from rootly_sdk.api.webhooks_endpoints import list_webhooks_endpoints
from rootly_sdk.api.secrets import list_secrets
from rootly_sdk.api.status_pages import list_status_pages
from rootly_sdk.api.status_page_templates import list_status_page_templates
from rootly_sdk.api.form_fields import list_form_fields
from rootly_sdk.api.form_field_options import list_form_field_options
from rootly_sdk.api.form_field_positions import list_form_field_positions
from rootly_sdk.api.custom_forms import list_custom_forms
from rootly_sdk.api.incident_permission_sets import list_incident_permission_sets
from rootly_sdk.api.incident_permission_set_booleans import list_incident_permission_set_booleans
from rootly_sdk.api.incident_permission_set_resources import list_incident_permission_set_resources
from rootly_sdk.api.workflows import list_workflows
from rootly_sdk.api.workflow_groups import list_workflow_groups
from rootly_sdk.api.retrospective_templates import list_postmortem_templates
from rootly_sdk.api.retrospective_processes import list_retrospective_processes
from rootly_sdk.api.retrospective_steps import list_retrospective_steps
from rootly_sdk.api.retrospective_configurations import list_retrospective_configurations
from rootly_sdk.api.dashboards import list_dashboards
from rootly_sdk.api.dashboard_panels import list_dashboard_panels
from rootly_sdk.api.escalation_paths import list_escalation_paths
from rootly_sdk.api.escalation_levels_path import list_escalation_levels_paths
from rootly_sdk.models.action_item_trigger_params import ActionItemTriggerParams
from rootly_sdk.models.alert_trigger_params import AlertTriggerParams
from rootly_sdk.models.incident_trigger_params import IncidentTriggerParams
from rootly_sdk.models.pulse_trigger_params import PulseTriggerParams
from rootly_sdk.models.simple_trigger_params import SimpleTriggerParams

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

# Common server-generated fields present on most resources.
_COMMON_READ_ONLY = {"created_at", "updated_at"}

# Per-type additional read-only fields (beyond _COMMON_READ_ONLY).
# slug is auto-generated from name on create, so strip it to avoid conflicts on re-import.
_SLUG_FIELD = {"slug"}
_WEBHOOK_READ_ONLY        = _COMMON_READ_ONLY | _SLUG_FIELD | {"secret"}   # server-generated HMAC secret
_POST_MORTEM_READ_ONLY    = _COMMON_READ_ONLY | _SLUG_FIELD | {"content_html", "content_json"}  # derived render fields
_WORKFLOW_READ_ONLY       = _COMMON_READ_ONLY | _SLUG_FIELD | {"created_by_user_id", "last_updated_by_user_id"}

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


# --- Generic fetch helpers for Pulumi-import coverage ---

def _fetch_paginated_list(client: AuthenticatedClient, list_fn, label: str) -> list:
    """Generic paginated top-level resource fetcher.

    Works with any list function whose sync_detailed() accepts ``client``,
    ``pagenumber``, and ``pagesize`` and returns a response whose ``.parsed``
    has a ``.data`` list and an optional ``.links.next_`` sentinel.
    """
    items = []
    page = 1
    while True:
        response = list_fn.sync_detailed(client=client, pagenumber=page, pagesize=100)
        if response.status_code != 200 or response.parsed is None:
            print(f"  Error fetching {label} (page {page}): {response.status_code}")
            break
        items.extend(response.parsed.data)
        links = getattr(response.parsed, "links", None)
        if links is None or links.next_ is None:
            break
        page += 1
    return items


def _fetch_sub_resource_list(client: AuthenticatedClient, list_fn, parent_items: list, label: str) -> list:
    """Generic sub-resource fetcher.

    For each item in *parent_items*, calls ``list_fn.sync_detailed(parent.id, …)``
    and collects all paginated results.  The parent ID is passed as the first
    positional argument, matching the SDK's convention for every child endpoint.
    """
    items = []
    for parent in parent_items:
        page = 1
        while True:
            response = list_fn.sync_detailed(str(parent.id), client=client, pagenumber=page, pagesize=100)
            if response.status_code != 200 or response.parsed is None:
                print(f"  Error fetching {label} for parent {parent.id}: {response.status_code}")
                break
            items.extend(response.parsed.data)
            links = getattr(response.parsed, "links", None)
            if links is None or links.next_ is None:
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


def _generic_to_writable_dict(item, read_only: set | None = None) -> dict:
    """Generic writable-dict extractor for resources with no special nesting.

    Uses the SDK's own to_dict() for correct enum/UUID serialisation, then
    strips the specified read-only fields (default: created_at + updated_at).
    None values are removed so the resulting dict stays compact.
    """
    d = item.attributes.to_dict()
    for key in (read_only if read_only is not None else _COMMON_READ_ONLY):
        d.pop(key, None)
    return {k: v for k, v in d.items() if v is not None}


def workflow_to_writable_dict(item) -> dict:
    """Extract only writable attributes from a WorkflowListDataItem."""
    d = item.attributes.to_dict()
    for key in _WORKFLOW_READ_ONLY:
        d.pop(key, None)
    return {k: v for k, v in d.items() if v is not None}


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

    def _fetch_and_convert(label: str, list_fn, converter) -> list:
        """Fetch a paginated top-level resource and apply converter."""
        print(f"Fetching all {label}...")
        items = _fetch_paginated_list(client, list_fn, label)
        converted = [converter(i) for i in items]
        print(f"  Fetched {len(converted)} {label}.")
        return converted

    # --- existing resources ---
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

    # --- newly covered resources ---
    _ro = _COMMON_READ_ONLY | _SLUG_FIELD  # strip created_at/updated_at/slug for most

    environments          = _fetch_and_convert("environments",           list_environments,           lambda i: _generic_to_writable_dict(i, _ro))
    severities            = _fetch_and_convert("severities",             list_severities,             lambda i: _generic_to_writable_dict(i, _ro))
    functionalities       = _fetch_and_convert("functionalities",        list_functionalities,        lambda i: _generic_to_writable_dict(i, _ro))
    causes                = _fetch_and_convert("causes",                 list_causes,                 lambda i: _generic_to_writable_dict(i, _ro))
    incident_types        = _fetch_and_convert("incident types",         list_incident_types,         lambda i: _generic_to_writable_dict(i, _ro))
    incident_roles        = _fetch_and_convert("incident roles",         list_incident_roles,         lambda i: _generic_to_writable_dict(i, _ro))
    schedules             = _fetch_and_convert("schedules",              list_schedules,              lambda i: _generic_to_writable_dict(i, _COMMON_READ_ONLY))
    playbooks             = _fetch_and_convert("playbooks",              list_playbooks,              lambda i: _generic_to_writable_dict(i, _COMMON_READ_ONLY))
    webhooks_endpoints    = _fetch_and_convert("webhooks endpoints",     list_webhooks_endpoints,     lambda i: _generic_to_writable_dict(i, _WEBHOOK_READ_ONLY))
    secrets               = _fetch_and_convert("secrets",               list_secrets,               lambda i: _generic_to_writable_dict(i, _COMMON_READ_ONLY))
    status_pages          = _fetch_and_convert("status pages",           list_status_pages,           lambda i: _generic_to_writable_dict(i, _ro))
    form_fields           = _fetch_and_convert("form fields",            list_form_fields,            lambda i: _generic_to_writable_dict(i, _ro))
    custom_forms          = _fetch_and_convert("custom forms",           list_custom_forms,           lambda i: _generic_to_writable_dict(i, _ro))
    incident_permission_sets = _fetch_and_convert("incident permission sets", list_incident_permission_sets, lambda i: _generic_to_writable_dict(i, _ro))
    workflows             = _fetch_and_convert("workflows",              list_workflows,              workflow_to_writable_dict)
    workflow_groups       = _fetch_and_convert("workflow groups",        list_workflow_groups,        lambda i: _generic_to_writable_dict(i, _ro))
    postmortem_templates  = _fetch_and_convert("post-mortem templates",  list_postmortem_templates,   lambda i: _generic_to_writable_dict(i, _POST_MORTEM_READ_ONLY))
    retrospective_processes = _fetch_and_convert("retrospective processes", list_retrospective_processes, lambda i: _generic_to_writable_dict(i, _COMMON_READ_ONLY))
    retrospective_configurations = _fetch_and_convert("retrospective configurations", list_retrospective_configurations, lambda i: _generic_to_writable_dict(i, _COMMON_READ_ONLY))
    dashboards            = _fetch_and_convert("dashboards",             list_dashboards,             lambda i: _generic_to_writable_dict(i, _COMMON_READ_ONLY))

    def fmt(obj):
        return pprint.pformat(obj, indent=4, sort_dicts=False)

    content = (
        f"SERVICES = {fmt(services)}\n\n"
        f"ROLES = {fmt(roles)}\n\n"
        f"TEAMS = {fmt(teams)}\n\n"
        f"ALERT_SOURCES = {fmt(alert_sources)}\n\n"
        f"ALERT_ROUTES = {fmt(alert_routes)}\n\n"
        f"ESCALATION_POLICIES = {fmt(escalation_policies)}\n\n"
        f"ENVIRONMENTS = {fmt(environments)}\n\n"
        f"SEVERITIES = {fmt(severities)}\n\n"
        f"FUNCTIONALITIES = {fmt(functionalities)}\n\n"
        f"CAUSES = {fmt(causes)}\n\n"
        f"INCIDENT_TYPES = {fmt(incident_types)}\n\n"
        f"INCIDENT_ROLES = {fmt(incident_roles)}\n\n"
        f"SCHEDULES = {fmt(schedules)}\n\n"
        f"PLAYBOOKS = {fmt(playbooks)}\n\n"
        f"WEBHOOKS_ENDPOINTS = {fmt(webhooks_endpoints)}\n\n"
        f"SECRETS = {fmt(secrets)}\n\n"
        f"STATUS_PAGES = {fmt(status_pages)}\n\n"
        f"FORM_FIELDS = {fmt(form_fields)}\n\n"
        f"CUSTOM_FORMS = {fmt(custom_forms)}\n\n"
        f"INCIDENT_PERMISSION_SETS = {fmt(incident_permission_sets)}\n\n"
        f"WORKFLOWS = {fmt(workflows)}\n\n"
        f"WORKFLOW_GROUPS = {fmt(workflow_groups)}\n\n"
        f"POSTMORTEM_TEMPLATES = {fmt(postmortem_templates)}\n\n"
        f"RETROSPECTIVE_PROCESSES = {fmt(retrospective_processes)}\n\n"
        f"RETROSPECTIVE_CONFIGURATIONS = {fmt(retrospective_configurations)}\n\n"
        f"DASHBOARDS = {fmt(dashboards)}\n"
    )

    with open(DATA_FILE, "w") as f:
        f.write(content)

    new_counts = {
        "environments": len(environments),
        "severities": len(severities),
        "functionalities": len(functionalities),
        "causes": len(causes),
        "incident_types": len(incident_types),
        "incident_roles": len(incident_roles),
        "schedules": len(schedules),
        "playbooks": len(playbooks),
        "webhooks_endpoints": len(webhooks_endpoints),
        "secrets": len(secrets),
        "status_pages": len(status_pages),
        "form_fields": len(form_fields),
        "custom_forms": len(custom_forms),
        "incident_permission_sets": len(incident_permission_sets),
        "workflows": len(workflows),
        "workflow_groups": len(workflow_groups),
        "postmortem_templates": len(postmortem_templates),
        "retrospective_processes": len(retrospective_processes),
        "retrospective_configurations": len(retrospective_configurations),
        "dashboards": len(dashboards),
    }
    total_new = sum(new_counts.values())
    print(
        f"\nWrote {len(services)} services, {len(roles)} roles, {len(teams)} teams, "
        f"{len(alert_sources)} alert sources, {len(alert_routes)} alert routes, "
        f"{len(escalation_policies)} escalation policies, and "
        f"{total_new} additional resources ({', '.join(f'{v} {k}' for k, v in new_counts.items() if v)}) "
        f"to {DATA_FILE}"
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
    """Dynamically load all resource lists from a Python data file.

    Returns the six resource lists that ``run_import`` manages.  Additional
    variables written by ``--export`` (ENVIRONMENTS, WORKFLOWS, etc.) are
    present in the module but not returned here; they serve as a read-only
    reference snapshot.
    """
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
    # --- already-managed resources ---
    "alert_source":                     "rootly:index/alertsSource:AlertsSource",
    "alert_route":                      "rootly:index/alertRoute:AlertRoute",
    "service":                          "rootly:index/service:Service",
    "role":                             "rootly:index/role:Role",
    "team":                             "rootly:index/team:Team",
    "escalation_policy":                "rootly:index/escalationPolicy:EscalationPolicy",
    # --- incident / on-call configuration ---
    "environment":                      "rootly:index/environment:Environment",
    "severity":                         "rootly:index/severity:Severity",
    "functionality":                    "rootly:index/functionality:Functionality",
    "cause":                            "rootly:index/cause:Cause",
    "incident_type":                    "rootly:index/incidentType:IncidentType",
    "incident_role":                    "rootly:index/incidentRole:IncidentRole",
    "incident_role_task":               "rootly:index/incidentRoleTask:IncidentRoleTask",
    "incident_permission_set":          "rootly:index/incidentPermissionSet:IncidentPermissionSet",
    "incident_permission_set_boolean":  "rootly:index/incidentPermissionSetBoolean:IncidentPermissionSetBoolean",
    "incident_permission_set_resource": "rootly:index/incidentPermissionSetResource:IncidentPermissionSetResource",
    # --- scheduling ---
    "schedule":                         "rootly:index/schedule:Schedule",
    "schedule_rotation":                "rootly:index/scheduleRotation:ScheduleRotation",
    "schedule_rotation_active_time":    "rootly:index/scheduleRotationActiveTime:ScheduleRotationActiveTime",
    "schedule_rotation_user":           "rootly:index/scheduleRotationUser:ScheduleRotationUser",
    # --- escalation ---
    "escalation_level":                 "rootly:index/escalationLevel:EscalationLevel",
    # --- playbooks ---
    "playbook":                         "rootly:index/playbook:Playbook",
    "playbook_task":                    "rootly:index/playbookTask:PlaybookTask",
    # --- integrations ---
    "webhooks_endpoint":                "rootly:index/webhooksEndpoint:WebhooksEndpoint",
    "secret":                           "rootly:index/secret:Secret",
    # --- status pages ---
    "status_page":                      "rootly:index/statusPage:StatusPage",
    "status_page_template":             "rootly:index/statusPageTemplate:StatusPageTemplate",
    # --- forms ---
    "form_field":                       "rootly:index/formField:FormField",
    "form_field_option":                "rootly:index/formFieldOption:FormFieldOption",
    "form_field_position":              "rootly:index/formFieldPosition:FormFieldPosition",
    "custom_form":                      "rootly:index/customForm:CustomForm",
    # --- workflows ---
    "workflow_action_item":             "rootly:index/workflowActionItem:WorkflowActionItem",
    "workflow_alert":                   "rootly:index/workflowAlert:WorkflowAlert",
    "workflow_incident":                "rootly:index/workflowIncident:WorkflowIncident",
    "workflow_post_mortem":             "rootly:index/workflowPostMortem:WorkflowPostMortem",
    "workflow_pulse":                   "rootly:index/workflowPulse:WorkflowPulse",
    "workflow_simple":                  "rootly:index/workflowSimple:WorkflowSimple",
    "workflow_group":                   "rootly:index/workflowGroup:WorkflowGroup",
    # --- retrospectives ---
    "postmortem_template":              "rootly:index/postMortemTemplate:PostMortemTemplate",
    "retrospective_process":            "rootly:index/retrospectiveProcess:RetrospectiveProcess",
    "retrospective_step":               "rootly:index/retrospectiveStep:RetrospectiveStep",
    "retrospective_configuration":      "rootly:index/retrospectiveConfiguration:RetrospectiveConfiguration",
    # --- dashboards ---
    "dashboard":                        "rootly:index/dashboard:Dashboard",
    "dashboard_panel":                  "rootly:index/dashboardPanel:DashboardPanel",
}

# Maps trigger_params SDK class → Pulumi workflow kind.
# NOTE: The SDK's Workflow model does not parse PostMortemTriggerParams; any
# workflow whose trigger_params is UNSET or not one of these five classes will
# be emitted with a warning and mapped to workflow_simple as a safe fallback.
_TRIGGER_PARAMS_TO_KIND: list[tuple] = [
    (ActionItemTriggerParams, "workflow_action_item"),
    (AlertTriggerParams,      "workflow_alert"),
    (IncidentTriggerParams,   "workflow_incident"),
    (PulseTriggerParams,      "workflow_pulse"),
    (SimpleTriggerParams,     "workflow_simple"),
]


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


def _build_workflow_import_entries(items: list) -> list[dict]:
    """Build Pulumi import entries for workflow items.

    The Rootly API returns all workflow types from a single endpoint, but the
    Pulumi provider exposes them as distinct resource types (WorkflowIncident,
    WorkflowAlert, etc.).  We detect the correct type by inspecting the
    trigger_params SDK class.

    The SDK's Workflow model does not parse PostMortemTriggerParams, so those
    workflows will have trigger_params=UNSET after parsing.  We emit a warning
    and fall back to WorkflowSimple so that the resource is still included in
    the import file rather than silently dropped.
    """
    entries = []
    seen_names: dict[str, int] = {}
    for item in items:
        tp = item.attributes.trigger_params
        kind = None
        for cls, k in _TRIGGER_PARAMS_TO_KIND:
            if isinstance(tp, cls):
                kind = k
                break
        if kind is None:
            name_hint = getattr(item.attributes, "name", None) or str(item.id)
            print(
                f"  Warning: workflow '{name_hint}' (id={item.id}) has an unrecognised "
                f"trigger_params type ({type(tp).__name__}); mapping as WorkflowSimple. "
                f"If this is a post-mortem workflow, update the Pulumi type manually."
            )
            kind = "workflow_simple"
        pulumi_type = _PULUMI_TYPE[kind]
        display_name = getattr(item.attributes, "name", None) or str(item.id)
        base_slug = _slugify(str(display_name))
        count = seen_names.get(base_slug, 0)
        seen_names[base_slug] = count + 1
        slug = base_slug if count == 0 else f"{base_slug}-{count}"
        entries.append({
            "type": pulumi_type,
            "name": slug,
            "id": str(item.id),
            "logicalName": display_name,
        })
    return entries


def export_pulumi_imports(client: AuthenticatedClient, output_path: str) -> None:
    """Fetch all Rootly resources and write a Pulumi bulk-import JSON file.

    Covers every resource type supported by the Rootly Pulumi provider (v1.5.0)
    that can be enumerated via the Rootly REST API, including sub-resources that
    require parent-ID iteration (playbook tasks, schedule rotations, etc.).

    This function is strictly read-only — it calls only list/get endpoints and
    does not create, update, or delete anything in Rootly or Pulumi.
    """
    print("Fetching resources from Rootly (read-only)...")
    all_entries: list[dict] = []
    counts: dict[str, int] = {}

    def _add(kind: str, items: list) -> None:
        all_entries.extend(_build_import_entries(kind, items))
        counts[kind] = len(items)

    def _fetch(label: str, list_fn) -> list:
        print(f"  {label}...")
        return _fetch_paginated_list(client, list_fn, label)

    def _fetch_sub(label: str, list_fn, parent_items: list) -> list:
        print(f"  {label}...")
        return _fetch_sub_resource_list(client, list_fn, parent_items, label)

    # --- Top-level resources (no parent required) ---
    alert_source_items = fetch_all_alert_sources(client)
    _add("alert_source", alert_source_items)

    _add("alert_route", fetch_all_alert_routes(client))

    service_items = fetch_all_services(client)
    _add("service", service_items)

    _add("role", fetch_all_roles(client))

    _add("team", fetch_all_teams(client))

    escalation_policy_items = fetch_all_escalation_policies(client)
    _add("escalation_policy", escalation_policy_items)

    _add("environment",             _fetch("environments",             list_environments))
    _add("severity",                _fetch("severities",               list_severities))
    _add("functionality",           _fetch("functionalities",          list_functionalities))
    _add("cause",                   _fetch("causes",                   list_causes))
    _add("incident_type",           _fetch("incident types",           list_incident_types))

    incident_role_items = _fetch("incident roles", list_incident_roles)
    _add("incident_role", incident_role_items)

    incident_permission_set_items = _fetch("incident permission sets", list_incident_permission_sets)
    _add("incident_permission_set", incident_permission_set_items)

    schedule_items = _fetch("schedules", list_schedules)
    _add("schedule", schedule_items)

    playbook_items = _fetch("playbooks", list_playbooks)
    _add("playbook", playbook_items)

    _add("webhooks_endpoint",   _fetch("webhooks endpoints",   list_webhooks_endpoints))
    _add("secret",              _fetch("secrets",              list_secrets))

    status_page_items = _fetch("status pages", list_status_pages)
    _add("status_page", status_page_items)

    form_field_items = _fetch("form fields", list_form_fields)
    _add("form_field", form_field_items)

    _add("custom_form",         _fetch("custom forms",         list_custom_forms))

    # Workflows — use the type-aware builder instead of _add.
    print("  workflows...")
    workflow_items = _fetch_paginated_list(client, list_workflows, "workflows")
    workflow_entries = _build_workflow_import_entries(workflow_items)
    all_entries.extend(workflow_entries)
    counts["workflows"] = len(workflow_items)

    _add("workflow_group",      _fetch("workflow groups",      list_workflow_groups))

    retrospective_process_items = _fetch("retrospective processes", list_retrospective_processes)
    _add("retrospective_process", retrospective_process_items)

    _add("retrospective_configuration", _fetch("retrospective configurations", list_retrospective_configurations))
    _add("postmortem_template",         _fetch("post-mortem templates",        list_postmortem_templates))

    dashboard_items = _fetch("dashboards", list_dashboards)
    _add("dashboard", dashboard_items)

    # --- Sub-resources (one level deep; keyed by parent) ---

    _add("incident_role_task",
         _fetch_sub("incident role tasks", list_incident_role_tasks, incident_role_items))

    _add("incident_permission_set_boolean",
         _fetch_sub("incident permission set booleans",
                    list_incident_permission_set_booleans, incident_permission_set_items))

    _add("incident_permission_set_resource",
         _fetch_sub("incident permission set resources",
                    list_incident_permission_set_resources, incident_permission_set_items))

    schedule_rotation_items = _fetch_sub("schedule rotations", list_schedule_rotations, schedule_items)
    _add("schedule_rotation", schedule_rotation_items)

    _add("form_field_option",
         _fetch_sub("form field options", list_form_field_options, form_field_items))

    _add("form_field_position",
         _fetch_sub("form field positions", list_form_field_positions, form_field_items))

    _add("playbook_task",
         _fetch_sub("playbook tasks", list_playbook_tasks, playbook_items))

    _add("status_page_template",
         _fetch_sub("status page templates", list_status_page_templates, status_page_items))

    _add("dashboard_panel",
         _fetch_sub("dashboard panels", list_dashboard_panels, dashboard_items))

    _add("retrospective_step",
         _fetch_sub("retrospective steps", list_retrospective_steps, retrospective_process_items))

    # --- Sub-sub-resources (two levels deep) ---

    # Escalation levels: policy → escalation path → escalation level.
    print("  escalation paths (per policy)...")
    escalation_path_items = _fetch_sub_resource_list(
        client, list_escalation_paths, escalation_policy_items, "escalation paths"
    )
    print("  escalation levels (per path)...")
    _add("escalation_level",
         _fetch_sub_resource_list(
             client, list_escalation_levels_paths, escalation_path_items, "escalation levels"
         ))

    # Schedule rotation memberships: schedule → rotation → users / active-time slots.
    _add("schedule_rotation_active_time",
         _fetch_sub("schedule rotation active times",
                    list_schedule_rotation_active_days, schedule_rotation_items))

    _add("schedule_rotation_user",
         _fetch_sub("schedule rotation users",
                    list_schedule_rotation_users, schedule_rotation_items))

    # --- Write output ---
    import_doc = {"resources": all_entries}
    with open(output_path, "w") as f:
        json.dump(import_doc, f, indent=2)

    total = sum(counts.values())
    print(f"\nWrote {total} import entries to {output_path}:")
    for kind, count in sorted(counts.items()):
        if count:
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
