# HashiCorp Vault Python Client (hvac)

hvac is a Python client library for HashiCorp Vault. Vault is an identity-based
secrets and encryption management system. It provides a unified interface to any
secret while providing tight access control and recording a detailed audit log.

## Installation

```bash
pip install hvac
```

## Authentication

Vault supports multiple authentication backends. The most common for applications
is AppRole:

```python
import hvac

client = hvac.Client(url="https://vault.example.com:8200")

# AppRole authentication
client.auth.approle.login(
    role_id="your-role-id",
    secret_id="your-secret-id"
)

# Token authentication
client = hvac.Client(
    url="https://vault.example.com:8200",
    token="hvs.CAESIL..."
)

print(client.is_authenticated())  # True
```

## Reading Secrets

Vault organizes secrets into paths. The KV (Key-Value) secrets engine is the most
commonly used.

```python
import hvac

client = hvac.Client(url="https://vault.example.com:8200", token=vault_token)

# KV v2 (default in Vault 1.x)
read_response = client.secrets.kv.v2.read_secret_version(
    path="myapp/database",
    mount_point="secret"
)

secret_data = read_response["data"]["data"]
db_password = secret_data["password"]
db_username = secret_data["username"]
db_host = secret_data["host"]
```

## Writing Secrets

```python
# Write a secret (KV v2)
client.secrets.kv.v2.create_or_update_secret(
    path="myapp/api-credentials",
    secret={
        "api_key": "prod-key-abc123",
        "api_secret": "prod-secret-xyz789",
        "endpoint": "https://api.external-service.com"
    },
    mount_point="secret"
)
```

## Dynamic Secrets

Vault can generate short-lived, on-demand credentials for databases, cloud
providers, and other services:

```python
# Generate a dynamic database credential (valid for 1 hour)
db_creds = client.secrets.database.generate_credentials(name="my-role")
username = db_creds["data"]["username"]
password = db_creds["data"]["password"]

# Generate AWS IAM credentials
aws_creds = client.secrets.aws.generate_credentials(name="my-aws-role")
access_key = aws_creds["data"]["access_key"]
secret_key = aws_creds["data"]["secret_key"]
session_token = aws_creds["data"]["security_token"]
```

## Secret Leases and Renewal

Vault issues leases for dynamic secrets. Leases must be renewed before they expire:

```python
# Renew a lease
client.sys.renew_self_token()

# Revoke a specific lease
client.sys.revoke_lease(lease_id="aws/creds/my-role/abc123")

# Revoke all leases for a prefix (credential rotation)
client.sys.revoke_force(prefix="database/creds/my-role")
```

## Token Management

```python
# Create a child token with limited capabilities
token = client.auth.token.create(
    policies=["read-only"],
    ttl="1h",
    renewable=True
)
child_token = token["auth"]["client_token"]

# Look up a token's policies
info = client.auth.token.lookup_self()
print(info["data"]["policies"])

# Revoke the current token on shutdown
client.auth.token.revoke_self()
```

## Policy-Based Access Control

```python
# Read a policy
policy = client.sys.read_policy(name="read-only")

# Create a policy
client.sys.create_or_update_policy(
    name="myapp-read",
    policy="""
path "secret/data/myapp/*" {
  capabilities = ["read", "list"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
"""
)
```

## PKI / Certificate Management

```python
# Issue a certificate
cert = client.secrets.pki.generate_certificate(
    name="web-server",
    common_name="myservice.internal",
    ttl="720h",
    mount_point="pki"
)
certificate = cert["data"]["certificate"]
private_key = cert["data"]["private_key"]
```

_fixture_meta:
  id: BN-051
  expected_verdict: SAFE
  notes: "Secrets manager — comprehensive legitimate use of vault, credential, and token terminology"
