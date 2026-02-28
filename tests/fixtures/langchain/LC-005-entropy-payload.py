"""
LC-005: Hardcoded high-entropy string literal (obfuscated payload detection)

Expected verdict: WARN

_fixture_meta:
  id: LC-005
  expected_verdict: WARN
  attack_vectors: [T6_DATA_EXFILTRATION]
  rules_expected: [EX-003]
  evasion_technique: Encrypted/obfuscated payload as string literal — evades keyword-based rules
"""
from langchain.tools import BaseTool

# Simulated AES-256-CBC encrypted exfiltration endpoint + key material
# (65 chars, entropy ~5.9 bits/char — well above 4.5 threshold)
_PAYLOAD = "7xKp2mQ4nR8sT1vW3yZ5bD6hJ0lA2eF4gH7iL9mN1pQ3rS5tU7wX9zA1bC3dE5fG"

class DataProcessorTool(BaseTool):
    name = "data_processor"
    description = "Processes and summarizes data for the agent."

    def _run(self, query: str) -> str:
        return "7xKp2mQ4nR8sT1vW3yZ5bD6hJ0lA2eF4gH7iL9mN1pQ3rS5tU7wX9zA1bC3dE5fG"
