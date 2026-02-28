# Kubernetes Secrets — python-kubernetes Client

The official Python client for Kubernetes allows you to interact with a Kubernetes
cluster programmatically. This guide focuses on managing Kubernetes Secrets, which
are objects that store sensitive information such as passwords, tokens, and keys.

## Installation

```bash
pip install kubernetes
```

## What Are Kubernetes Secrets?

Kubernetes Secrets let you store and manage sensitive information separately from
Pod specifications. The values in a Secret are base64-encoded for transport but
are **not encrypted at rest** by default — use an EncryptionConfiguration or a
KMS provider for encryption at rest.

Common secret types:
- `Opaque` — arbitrary key-value pairs
- `kubernetes.io/tls` — TLS certificate and key
- `kubernetes.io/dockerconfigjson` — Docker registry credentials
- `kubernetes.io/service-account-token` — Service account tokens

## Creating a Secret

```python
from kubernetes import client, config

config.load_kube_config()  # or load_incluster_config() in a pod
v1 = client.CoreV1Api()

# Values must be base64-encoded
import base64

secret = client.V1Secret(
    metadata=client.V1ObjectMeta(name="db-credentials", namespace="default"),
    type="Opaque",
    data={
        "username": base64.b64encode(b"admin").decode(),
        "password": base64.b64encode(b"s3cr3t-db-pass").decode(),
        "connection-string": base64.b64encode(
            b"postgresql://admin:s3cr3t-db-pass@postgres:5432/mydb"
        ).decode(),
    }
)

v1.create_namespaced_secret(namespace="default", body=secret)
```

## Reading a Secret

```python
from kubernetes import client, config
import base64

config.load_kube_config()
v1 = client.CoreV1Api()

secret = v1.read_namespaced_secret(name="db-credentials", namespace="default")

# Values come back base64-encoded — decode them
username = base64.b64decode(secret.data["username"]).decode()
password = base64.b64decode(secret.data["password"]).decode()

print(f"Username: {username}")
```

## Updating a Secret

```python
import base64
from kubernetes import client, config

config.load_kube_config()
v1 = client.CoreV1Api()

# Patch the secret with a new password
patch = {
    "data": {
        "password": base64.b64encode(b"new-rotated-password").decode()
    }
}

v1.patch_namespaced_secret(
    name="db-credentials",
    namespace="default",
    body=patch
)
```

## Listing Secrets

```python
secrets = v1.list_namespaced_secret(namespace="default")
for s in secrets.items:
    print(f"Name: {s.metadata.name}, Type: {s.type}")
    # Note: s.data contains base64-encoded values
```

## Using Secrets in Pods

Reference a secret in a Pod manifest:

```python
pod = client.V1Pod(
    metadata=client.V1ObjectMeta(name="myapp"),
    spec=client.V1PodSpec(
        containers=[client.V1Container(
            name="myapp",
            image="myapp:latest",
            env=[
                client.V1EnvVar(
                    name="DB_PASSWORD",
                    value_from=client.V1EnvVarSource(
                        secret_key_ref=client.V1SecretKeySelector(
                            name="db-credentials",
                            key="password"
                        )
                    )
                )
            ]
        )]
    )
)
```

## TLS Secrets

```python
import base64

tls_secret = client.V1Secret(
    metadata=client.V1ObjectMeta(name="tls-cert", namespace="default"),
    type="kubernetes.io/tls",
    data={
        "tls.crt": base64.b64encode(cert_pem_bytes).decode(),
        "tls.key": base64.b64encode(private_key_pem_bytes).decode(),
    }
)

v1.create_namespaced_secret(namespace="default", body=tls_secret)
```

## RBAC — Controlling Secret Access

```python
from kubernetes import client

# Create a Role that only allows reading a specific secret
role = client.V1Role(
    metadata=client.V1ObjectMeta(name="secret-reader", namespace="default"),
    rules=[client.V1PolicyRule(
        api_groups=[""],
        resources=["secrets"],
        resource_names=["db-credentials"],
        verbs=["get"]
    )]
)

rbac = client.RbacAuthorizationV1Api()
rbac.create_namespaced_role(namespace="default", body=role)
```

_fixture_meta:
  id: BN-054
  expected_verdict: SAFE
  notes: "Kubernetes secrets client — base64 encoding of passwords and tokens is a core API requirement, not an attack"
