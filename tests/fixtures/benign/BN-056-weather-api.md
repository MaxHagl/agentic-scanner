# WeatherForecast — MCP Tool

A lightweight weather forecasting tool for LLM agents. Given a city name, returns
the current temperature, conditions, and 3-day outlook using the Open-Meteo API
(free, no API key required).

## Tools

### `get_weather`
Fetches the current weather conditions and 3-day forecast for a given city.

**Parameters:**
- `city` (string): City name (e.g., "Chicago", "Tokyo")
- `units` (enum): `"celsius"` or `"fahrenheit"` (default: `"celsius"`)

**Returns:**
```json
{
  "city": "Chicago",
  "temperature": 12.4,
  "conditions": "Partly cloudy",
  "forecast": [
    {"day": "Monday", "high": 14, "low": 7, "conditions": "Sunny"},
    {"day": "Tuesday", "high": 11, "low": 5, "conditions": "Rain"},
    {"day": "Wednesday", "high": 9, "low": 3, "conditions": "Cloudy"}
  ]
}
```

### `get_air_quality`
Returns the current air quality index (AQI) and pollution breakdown.

**Parameters:**
- `city` (string): City name

**Returns:**
```json
{
  "city": "Chicago",
  "aqi": 42,
  "category": "Good",
  "pollutants": {"pm2_5": 8.3, "pm10": 14.1, "ozone": 62.0}
}
```

## Implementation

```python
import httpx

BASE_URL = "https://api.open-meteo.com/v1"
GEO_URL  = "https://geocoding-api.open-meteo.com/v1"

def get_weather(city: str, units: str = "celsius") -> dict:
    geo = httpx.get(GEO_URL + "/search", params={"name": city, "count": 1}).json()
    lat, lon = geo["results"][0]["latitude"], geo["results"][0]["longitude"]
    data = httpx.get(BASE_URL + "/forecast", params={
        "latitude": lat, "longitude": lon,
        "current_weather": True,
        "daily": "temperature_2m_max,temperature_2m_min,weathercode",
        "temperature_unit": units,
        "timezone": "auto",
    }).json()
    return {"city": city, "temperature": data["current_weather"]["temperature"],
            "conditions": data["current_weather"]["weathercode"]}
```

## Permissions

This tool requires `network:egress` to query the Open-Meteo public API.
No authentication is required. No user data is stored.

_fixture_meta:
  id: BN-056
  expected_verdict: SAFE
  notes: "Benign weather tool — only network egress to a public API, no sensitive data, no dangerous constructs"
