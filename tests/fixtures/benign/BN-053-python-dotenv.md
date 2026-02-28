# python-dotenv

python-dotenv reads key-value pairs from a `.env` file and sets them as
environment variables. It is the standard way to manage secrets and configuration
in Python applications without committing sensitive values to version control.

## Installation

```bash
pip install python-dotenv
```

## Basic Usage

Create a `.env` file in your project root:

```ini
# .env
DATABASE_URL=postgresql://user:password@localhost:5432/mydb
SECRET_KEY=your-flask-or-django-secret-key
API_KEY=your-third-party-api-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
```

Load the `.env` file at application startup:

```python
from dotenv import load_dotenv
import os

load_dotenv()  # Loads .env from current directory

database_url = os.getenv("DATABASE_URL")
secret_key = os.getenv("SECRET_KEY")
api_key = os.getenv("API_KEY")
```

**Important**: Always add `.env` to your `.gitignore`. Never commit secrets to git.

```
# .gitignore
.env
.env.*
!.env.example
```

## Providing Defaults

```python
from dotenv import load_dotenv
import os

load_dotenv()

# Provide a fallback for missing variables
debug = os.getenv("DEBUG", "False") == "True"
port = int(os.getenv("PORT", "8000"))
log_level = os.getenv("LOG_LEVEL", "INFO")
```

## Multiple Environments

```python
from dotenv import load_dotenv
import os

# Load the environment-specific file
env = os.getenv("APP_ENV", "development")
load_dotenv(f".env.{env}")

# .env.development, .env.staging, .env.production
```

## Finding the `.env` File

```python
from dotenv import load_dotenv, find_dotenv

# Automatically search parent directories for .env
load_dotenv(find_dotenv())

# Specify an explicit path
load_dotenv("/etc/myapp/.env")
```

## Override Existing Variables

By default, `load_dotenv` does not override existing environment variables
(so shell exports take precedence over `.env`):

```python
# Force override even if var is already set in the shell
load_dotenv(override=True)
```

## `dotenv_values` (no side effects)

Use `dotenv_values` when you want to read the file without setting env vars:

```python
from dotenv import dotenv_values

config = dotenv_values(".env")
print(config["DATABASE_URL"])
# Useful in tests or when you want explicit config objects
```

## Streaming / Dict Access

```python
from dotenv import dotenv_values

config = dotenv_values(".env.shared") | dotenv_values(".env.secret") | os.environ
# Later values override earlier ones — os.environ wins over .env files
```

## Generating an Example File

Best practice is to ship a `.env.example` that shows which variables are required
but with placeholder values:

```ini
# .env.example — copy to .env and fill in real values
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
SECRET_KEY=change-me-in-production
API_KEY=your-api-key-here
STRIPE_SECRET_KEY=sk_test_...
SENDGRID_API_KEY=SG....
```

## CLI Usage

```bash
# Run a command with .env variables loaded
dotenv run -- python manage.py runserver

# Get a specific variable
dotenv get SECRET_KEY

# Set a variable
dotenv set API_KEY "new-key-value"

# List all variables
dotenv list
```

_fixture_meta:
  id: BN-053
  expected_verdict: SAFE
  notes: "Env-var secrets loader — legitimately discusses API keys, passwords, and SECRET_KEY patterns"
