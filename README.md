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

This will import all resources into Pulumi state and generate Python code stubs. Review the generated code before committing — you will likely need to clean up read-only fields and wire up cross-resource references.
