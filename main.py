import os

from rootly_sdk import AuthenticatedClient
from rootly_sdk.api.services import create_service
from rootly_sdk.api.roles import create_role
from rootly_sdk.models.new_service import NewService
from rootly_sdk.models.new_role import NewRole


# Example data - named obviously for easy cleanup after testing
EXAMPLE_SERVICES = [
    {
        "name": "exampleDeleteMe-Service",
        "description": "Test service created by ol-rootly-models - safe to delete",
        "color": "#FF5733",
    },
]

EXAMPLE_ROLES = [
    {
        "name": "exampleDeleteMe-Role",
        "slug": "example-delete-me-role",
        "incidents_permissions": ["read"],
        "services_permissions": ["read"],
    },
]


def create_service_from_dict(client: AuthenticatedClient, service_dict: dict) -> None:
    """Create a Rootly service from a dictionary."""
    payload = NewService.from_dict({
        "data": {
            "type": "services",
            "attributes": service_dict,
        }
    })

    response = create_service.sync_detailed(client=client, body=payload)

    if response.status_code == 201:
        result = response.parsed
        print(f"Created service: {result.data.attributes.name} (id: {result.data.id})")
    else:
        print(f"Failed to create service '{service_dict['name']}': {response.status_code}")
        if response.parsed:
            print(f"  Error: {response.parsed}")


def create_role_from_dict(client: AuthenticatedClient, role_dict: dict) -> None:
    """Create a Rootly role from a dictionary."""
    payload = NewRole.from_dict({
        "data": {
            "type": "roles",
            "attributes": role_dict,
        }
    })

    response = create_role.sync_detailed(client=client, body=payload)

    if response.status_code == 201:
        result = response.parsed
        print(f"Created role: {result.data.attributes.name} (id: {result.data.id})")
    else:
        print(f"Failed to create role '{role_dict['name']}': {response.status_code}")
        if response.parsed:
            print(f"  Error: {response.parsed}")


def main():
    api_key = os.environ.get("ROOTLY_API_KEY")
    if not api_key:
        print("Error: ROOTLY_API_KEY environment variable not set")
        return

    client = AuthenticatedClient(
        base_url="https://api.rootly.com",
        token=api_key,
    )

    with client as client:
        print("Creating services...")
        for service_dict in EXAMPLE_SERVICES:
            create_service_from_dict(client, service_dict)

        print("\nCreating roles...")
        for role_dict in EXAMPLE_ROLES:
            create_role_from_dict(client, role_dict)


if __name__ == "__main__":
    main()
