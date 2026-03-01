"""
local_judge.py
──────────────
LocalLLMJudge: a finetuned local LoRA model as a fast Layer 2 pre-filter.

Design:
  - Runs BEFORE AnthropicJudgeClient (Haiku) in the Layer2Analyzer pipeline.
  - Returns a verdict directly when confidence ≥ threshold.
  - Escalates to Haiku when uncertain (confidence < threshold) or on PARSE_ERROR.
  - Reuses JudgeResponseParser.parse() — same JSON schema as Haiku outputs.
  - Imports transformers/peft lazily: zero overhead when --local-model is not passed.
  - Model is lazy-loaded once on the first call() and cached for reuse.

Security invariants:
  - wrap_untrusted() is applied by the Layer2Analyzer caller — this class receives
    the already-wrapped user_message and passes it through without modification.
  - PARSE_ERROR → is_confident() returns False → escalates to Haiku. Never fail-closed.
  - temperature=1.0 (do_sample=False) → deterministic greedy decoding.

Usage:
    from scanner.layer2_semantic.local_judge import LocalLLMJudge
    judge = LocalLLMJudge("finetuning/adapter", confidence_threshold=0.80)
    response = judge.call(system_prompt, user_message)
    if judge.is_confident(response):
        # use local verdict directly
        ...
    else:
        # escalate to Haiku
        ...
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from scanner.layer2_semantic.llm_judge import JudgeResponse, JudgeResponseParser

if TYPE_CHECKING:
    pass  # avoid runtime imports for type hints

logger = logging.getLogger(__name__)


class LocalLLMJudge:
    """
    Finetuned local LoRA model as a confidence-gated Layer 2 pre-filter.

    The model is lazy-loaded on the first call() to avoid startup overhead
    when --local-model is not used.

    Args:
        adapter_path: Path to the saved LoRA adapter directory
                      (produced by finetuning/train.py).
        confidence_threshold: Minimum confidence for the local model to
                              return a verdict without escalation (default 0.80).
        max_new_tokens: Max tokens the model generates per call (default 256).
    """

    def __init__(
        self,
        adapter_path: str | Path,
        confidence_threshold: float = 0.80,
        max_new_tokens: int = 128,   # JSON outputs are short; 256 wastes activation memory
    ) -> None:
        self._adapter_path = Path(adapter_path)
        self._threshold = confidence_threshold
        self._max_new_tokens = max_new_tokens

        # Lazy-loaded on first call
        self._model: Any = None
        self._tokenizer: Any = None
        self._torch: Any = None
        self._device: Any = None

    # ── Public API ────────────────────────────────────────────────────────────

    def call(self, system_prompt: str, user_message: str) -> JudgeResponse:
        """
        Run one inference pass and return a parsed JudgeResponse.

        On any error (model load failure, inference error, parse error),
        returns a JudgeResponse with verdict="PARSE_ERROR" — which causes
        is_confident() to return False and triggers Haiku escalation.
        """
        try:
            self._ensure_loaded()
            raw_text = self._generate(system_prompt, user_message)
            response = JudgeResponseParser.parse(raw_text)
            logger.debug(
                "LocalLLMJudge: verdict=%s confidence=%.2f",
                response.verdict,
                response.confidence,
            )
            return response
        except Exception as exc:
            logger.warning(
                "LocalLLMJudge: inference failed — will escalate to Haiku. Error: %s", exc
            )
            return JudgeResponse(
                verdict="PARSE_ERROR",
                confidence=0.0,
                attack_types=[],
                findings=[],
                rationale=f"LocalLLMJudge inference error: {str(exc)[:200]}",
                tokens_used=0,
            )

    def is_confident(self, response: JudgeResponse) -> bool:
        """
        Return True if the local model verdict should be used directly
        (no escalation to Haiku).

        Returns False when:
          - verdict == "PARSE_ERROR" (always escalate on parse failure)
          - confidence < threshold
        """
        if response.verdict == "PARSE_ERROR":
            return False
        return response.confidence >= self._threshold

    # ── Model loading ─────────────────────────────────────────────────────────

    def _ensure_loaded(self) -> None:
        """Lazy-load the model and tokenizer on first call."""
        if self._model is not None:
            return
        self._load_model()

    def _load_model(self) -> None:
        """
        Load base model + LoRA adapter.
        Imports transformers and peft lazily (not at module level).
        """
        logger.info("LocalLLMJudge: loading model from %s ...", self._adapter_path)

        try:
            import torch  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "torch is required for --local-model. Install with: pip install torch>=2.3"
            ) from exc

        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "transformers is required for --local-model. "
                "Install with: pip install transformers>=4.44"
            ) from exc

        try:
            from peft import PeftModel  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "peft is required for --local-model. Install with: pip install peft>=0.12"
            ) from exc

        import json

        # Resolve base model name from adapter provenance
        base_model = self._resolve_base_model(json)

        # Select device: MPS → CUDA → CPU
        if torch.backends.mps.is_available():
            device = torch.device("mps")
        elif torch.cuda.is_available():
            device = torch.device("cuda")
        else:
            device = torch.device("cpu")
            logger.warning("LocalLLMJudge: no GPU/MPS found — inference will be slow on CPU")

        logger.info("LocalLLMJudge: device=%s base_model=%s", device, base_model)

        tokenizer = AutoTokenizer.from_pretrained(
            str(self._adapter_path), trust_remote_code=True
        )
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        # float16 for inference (halves memory vs float32); low_cpu_mem_usage
        # streams shards directly to device instead of double-buffering in CPU RAM.
        base = AutoModelForCausalLM.from_pretrained(
            base_model,
            torch_dtype=torch.float16,
            trust_remote_code=True,
            attn_implementation="eager",
            low_cpu_mem_usage=True,
        ).to(device)

        model = PeftModel.from_pretrained(base, str(self._adapter_path))
        model.eval()

        self._torch = torch
        self._tokenizer = tokenizer
        self._model = model
        self._device = device
        logger.info("LocalLLMJudge: model loaded successfully")

    def _resolve_base_model(self, json_module: Any) -> str:
        """Read base model name from training provenance or adapter config."""
        provenance_file = self._adapter_path / "training_provenance.json"
        if provenance_file.exists():
            try:
                provenance = json_module.loads(provenance_file.read_text(encoding="utf-8"))
                return str(provenance["base_model"])
            except (KeyError, ValueError):
                pass

        adapter_config = self._adapter_path / "adapter_config.json"
        if adapter_config.exists():
            try:
                cfg = json_module.loads(adapter_config.read_text(encoding="utf-8"))
                return str(cfg["base_model_name_or_path"])
            except (KeyError, ValueError):
                pass

        logger.warning(
            "LocalLLMJudge: could not determine base model — defaulting to Phi-3.5-mini-instruct"
        )
        return "microsoft/Phi-3.5-mini-instruct"

    # ── Inference ─────────────────────────────────────────────────────────────

    def _generate(self, system_prompt: str, user_message: str) -> str:
        """Run one greedy-decode inference pass and return the generated text."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_message},
        ]

        prompt = self._tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )

        inputs = self._tokenizer(prompt, return_tensors="pt").to(self._device)

        with self._torch.no_grad():
            outputs = self._model.generate(
                **inputs,
                max_new_tokens=self._max_new_tokens,
                do_sample=False,
                temperature=1.0,  # do_sample=False makes temp irrelevant; explicit for clarity
                pad_token_id=self._tokenizer.eos_token_id,
                use_cache=False,  # avoids DynamicCache.seen_tokens AttributeError on transformers>=4.44
            )

        # Decode only newly generated tokens (not the prompt)
        generated_ids = outputs[0][inputs["input_ids"].shape[1]:]
        return self._tokenizer.decode(generated_ids, skip_special_tokens=True)
