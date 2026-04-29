# ol-rootly-manager

A Python CLI tool for managing Rootly resources (services, roles, teams, alert sources, alert routes, and escalation policies) via the Rootly API.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)
- A Rootly API key

## Setup

```bash
export ROOTLY_API_KEY=your_api_key_here
```

## Commands

### `--report`

Print a human-readable summary of all resources currently in Rootly.

```bash
uv run python main.py --report
```

### `--export`

Fetch all resources from Rootly and write them to `data.py` as Python data structures. This is read-only with respect to Rootly; it overwrites the local `data.py` file.

```bash
uv run python main.py --export
```

### `--import [FILE]`

Create or update Rootly resources from a Python data file (default: `data.py`). This is idempotent — existing resources are updated and missing ones are created.

```bash
uv run python main.py --import           # uses data.py
uv run python main.py --import my_data.py
```

### `--pulumi-import [FILE]`

Fetch all Rootly resources and write a [Pulumi bulk-import JSON file](https://www.pulumi.com/docs/cli/commands/pulumi_import/) (default: `pulumi_imports.json`).

**This command is strictly read-only — it does not create, update, or delete anything in Rootly or Pulumi.**

```bash
uv run python main.py --pulumi-import                  # writes pulumi_imports.json
uv run python main.py --pulumi-import my_imports.json  # writes to a custom path
```

The generated file contains one entry per resource with its Pulumi type, a slugified resource name, the Rootly UUID, and the original display name:

```json
{
  "resources": [
    {
      "type": "rootly:index/alertsSource:AlertsSource",
      "name": "my-alert-source",
      "id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "logicalName": "My Alert Source"
    }
  ]
}
```

Resource types included:

| Rootly resource     | Pulumi type                                  |
|---------------------|----------------------------------------------|
| Alert source        | `rootly:index/alertsSource:AlertsSource`     |
| Alert route         | `rootly:index/alertRoute:AlertRoute`         |
| Service             | `rootly:index/service:Service`               |
| Role                | `rootly:index/role:Role`                     |
| Team                | `rootly:index/team:Team`                     |
| Escalation policy   | `rootly:index/escalationPolicy:EscalationPolicy` |

#### Using the output with Pulumi

Once you have the import file, run the following from your Pulumi monitoring stack directory (e.g. `src/ol_infrastructure/infrastructure/monitoring/`):

```bash
pulumi import --file /path/to/pulumi_imports.json --generate-code
```

For each resource in the file, Pulumi will:

1. **Read the current live state** from Rootly via the provider
2. **Add it to Pulumi's state file** so Pulumi knows it manages that resource
3. **Generate a Python stub** with all current field values, for example:

```python
import pulumi_rootly as rootly

my_alert_source = rootly.AlertsSource(
    "my-alert-source",
    name="My Alert Source",
    source_type="datadog",
    alert_urgency_id="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    owner_group_ids=["yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"],
    # ... all other current fields
)
```

Review the generated code before committing — you may need to clean up read-only fields and wire up cross-resource references (e.g. replacing raw UUIDs with references to other imported resources).

#### The IaC management loop

Once resources are imported, the workflow for making changes is:

1. **Edit the Python** — change fields, add/remove values, etc.
2. **`pulumi preview`** — see exactly what will change in Rootly before touching anything
3. **`pulumi up`** — apply the changes

#### ⚠️ Important: Pulumi ownership

When you import a resource, Pulumi begins managing it. This means:

- If someone manually edits the resource in the Rootly UI, `pulumi up` will **revert it** back to what the Python says
- The team should commit to managing imported resources through Pulumi going forward, not through the UI

This is the desired end-state for IaC, but it's worth agreeing on as a team before importing everything.

#### Recommended approach: start small

Rather than importing all resources at once:

1. Pick **one alert source** as a trial run
2. Import just that resource and verify the generated Python looks correct
3. Run `pulumi preview` and confirm it shows **no changes** (meaning the imported state matches live reality)
4. Make a small test edit and run `pulumi preview` to confirm the diff looks right
5. Once confident, bulk-import the remaining resources
