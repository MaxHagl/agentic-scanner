# Docker SDK for Python

The Docker SDK for Python lets you do everything the `docker` command does, but from
within Python apps. Run containers, manage them, pull images, and interact with the
Docker daemon using a simple Python API.

## Installation

```bash
pip install docker
```

## Connecting to Docker

```python
import docker

# Connect to Docker daemon (default: unix:///var/run/docker.sock)
client = docker.from_env()

# Or connect to a remote Docker host
client = docker.DockerClient(base_url="tcp://remote-host:2375")
```

## Running Containers

```python
import docker

client = docker.from_env()

# Run a container and capture output
output = client.containers.run("alpine", "echo hello world")
print(output)
# b'hello world\n'

# Run in detached mode
container = client.containers.run(
    "ubuntu:20.04",
    "sleep infinity",
    detach=True,
    name="my-container"
)
print(container.id)
```

## Container Lifecycle Management

```python
import docker

client = docker.from_env()

# List running containers
containers = client.containers.list()
for container in containers:
    print(f"{container.name}: {container.status}")

# List all containers (including stopped)
all_containers = client.containers.list(all=True)

# Get a specific container
container = client.containers.get("my-container")

# Start, stop, restart
container.start()
container.stop(timeout=10)
container.restart()

# Remove a container
container.remove(force=True)
```

## Container Execution

```python
# Execute a command in a running container
container = client.containers.get("my-container")
exit_code, output = container.exec_run("ls /app", stream=False)
print(output.decode())

# Stream logs
for log_line in container.logs(stream=True, follow=True):
    print(log_line.decode().strip())
```

## Building Images

```python
import docker
import io

client = docker.from_env()

# Build from a Dockerfile path
image, build_logs = client.images.build(
    path="/path/to/project",
    tag="my-app:latest",
    rm=True
)

# Build from a file-like object
dockerfile = io.BytesIO(b"""
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "app.py"]
""")

image, logs = client.images.build(fileobj=dockerfile, tag="my-app:1.0")
```

## Image Management

```python
# Pull an image
image = client.images.pull("python:3.11-slim")

# List local images
images = client.images.list()

# Remove an image
client.images.remove("my-old-image:latest")

# Tag an image
image.tag("registry.example.com/my-app", tag="v1.0.0")

# Push to registry
client.images.push("registry.example.com/my-app", tag="v1.0.0")
```

## Networks and Volumes

```python
# Create a network
network = client.networks.create("my-network", driver="bridge")

# Run containers on the same network
container1 = client.containers.run(
    "nginx",
    detach=True,
    network="my-network",
    name="web"
)

# Create a volume
volume = client.volumes.create("my-data")

# Mount a volume
container = client.containers.run(
    "postgres:15",
    detach=True,
    volumes={"my-data": {"bind": "/var/lib/postgresql/data", "mode": "rw"}},
    environment={"POSTGRES_PASSWORD": "secretpassword"}
)
```

## Resource Limits and Isolation

Docker containers provide process isolation via Linux namespaces and cgroups:

```python
# Run with resource limits
container = client.containers.run(
    "python:3.11",
    "python script.py",
    detach=True,
    mem_limit="512m",
    cpu_period=100000,
    cpu_quota=50000,       # 50% of one CPU
    read_only=True,
    network_disabled=True, # No network access
    security_opt=["no-new-privileges:true"]
)
```

_fixture_meta:
  id: BN-049
  expected_verdict: SAFE
  notes: "Docker SDK mentioning container execution and isolation — must not trigger PE-006 on legitimate container management code"
