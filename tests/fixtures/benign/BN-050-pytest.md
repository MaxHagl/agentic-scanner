# pytest

pytest is a mature full-featured Python testing framework. It makes it easy to write
small, readable tests and can scale to support complex functional testing for applications
and libraries.

## Installation

```bash
pip install pytest
```

## Writing Tests

pytest discovers tests in files named `test_*.py` or `*_test.py`. Test functions must
be prefixed with `test_`.

```python
# test_math.py

def add(a, b):
    return a + b

def test_add():
    assert add(2, 3) == 5

def test_add_negative():
    assert add(-1, 1) == 0

def test_add_floats():
    assert abs(add(0.1, 0.2) - 0.3) < 1e-9
```

Run tests:
```bash
pytest
pytest test_math.py
pytest test_math.py::test_add
```

## Fixtures

Fixtures provide a way to supply test functions with setup data and resources. They
are declared with `@pytest.fixture` and can be shared across test files using `conftest.py`.

```python
import pytest

@pytest.fixture
def sample_user():
    return {"name": "Alice", "email": "alice@example.com", "age": 30}

@pytest.fixture
def database():
    db = create_test_database()
    yield db
    db.close()  # teardown runs after the test

def test_user_email(sample_user):
    assert "@" in sample_user["email"]

def test_user_creation(database, sample_user):
    user_id = database.create_user(sample_user)
    assert user_id is not None
```

## Parametrize

Run the same test with multiple inputs:

```python
import pytest

@pytest.mark.parametrize("input,expected", [
    ("hello", "HELLO"),
    ("world", "WORLD"),
    ("pytest", "PYTEST"),
])
def test_upper(input, expected):
    assert input.upper() == expected

@pytest.mark.parametrize("a,b,result", [
    (1, 2, 3),
    (0, 0, 0),
    (-1, 1, 0),
    (100, 200, 300),
])
def test_add(a, b, result):
    assert a + b == result
```

## Exception Testing

```python
import pytest

def divide(a, b):
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b

def test_divide_by_zero():
    with pytest.raises(ValueError, match="Cannot divide by zero"):
        divide(10, 0)

def test_divide_normal():
    assert divide(10, 2) == 5.0
```

## Markers

Use markers to categorize and selectively run tests:

```python
import pytest

@pytest.mark.slow
def test_large_dataset():
    ...  # This test takes a long time

@pytest.mark.integration
def test_database_connection():
    ...  # Requires a real database

@pytest.mark.skip(reason="Feature not implemented yet")
def test_future_feature():
    ...
```

Run only specific markers:
```bash
pytest -m "not slow"
pytest -m integration
```

## conftest.py

Share fixtures across multiple test files:

```python
# conftest.py (placed in the tests/ directory)
import pytest

@pytest.fixture(scope="session")
def app():
    """Create an application instance for the test session."""
    from myapp import create_app
    app = create_app({"TESTING": True, "DATABASE_URL": "sqlite:///:memory:"})
    return app

@pytest.fixture(scope="function")
def client(app):
    """Create a test client."""
    with app.test_client() as client:
        yield client
```

## Configuration (pytest.ini / pyproject.toml)

```ini
# pytest.ini
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
addopts = -v --tb=short
filterwarnings =
    error
    ignore::DeprecationWarning
```

Or in `pyproject.toml`:
```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = ["-v", "--tb=short"]
```

## Coverage

```bash
pip install pytest-cov
pytest --cov=myapp --cov-report=html tests/
```

## Mocking

```python
from unittest.mock import patch, MagicMock

def get_user_data(user_id: int) -> dict:
    response = requests.get(f"https://api.example.com/users/{user_id}")
    return response.json()

def test_get_user_data():
    mock_response = MagicMock()
    mock_response.json.return_value = {"id": 1, "name": "Alice"}

    with patch("requests.get", return_value=mock_response):
        result = get_user_data(1)
        assert result["name"] == "Alice"
```

_fixture_meta:
  id: BN-050
  expected_verdict: SAFE
  notes: "Pure testing framework — baseline negative with no security-relevant patterns"
