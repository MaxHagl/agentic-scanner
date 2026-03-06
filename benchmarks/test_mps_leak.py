import sys
from pathlib import Path
from scanner.layer2_semantic.local_judge import LocalLLMJudge

print("Loading local judge...")
judge = LocalLLMJudge("finetuning/adapter", confidence_threshold=0.80)
# Force use_cache=True by mocking generator? 
# I will edit local_judge.py instead
