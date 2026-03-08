"""
scanner/layer2_semantic/slm_judge.py
─────────────────────────────────────
SecuritySLMJudge: drop-in replacement for LocalLLMJudge using the from-scratch
350M RoPE encoder (no external pretrained weights).

Interface:
    judge = SecuritySLMJudge("finetuning/security_slm/", confidence_threshold=0.80)
    response = judge.call(system_prompt, user_message)
    if judge.is_confident(response):
        # use verdict directly
    else:
        # escalate to Haiku

Inference:
    Input text → custom BPE tokenizer → single encoder forward pass →
    softmax over 3 classes → argmax verdict + max-probability confidence.

    No token generation. No JSON parsing. No hallucination risk.
    Expected latency: < 10ms on GPU, < 30ms on CPU.

Supply-chain guarantee:
    Every weight in this model traces to a known, SHA256-logged source document.
    Zero external pretrained weights. Zero third-party model suppliers.

Differences from LocalLLMJudge:
  - No `transformers` or `peft` dependency (pure PyTorch + tokenizers)
  - Confidence = max softmax probability (not a self-reported float from JSON)
  - Findings/attack_types are always empty (single-pass classifier, no rationale)
  - The `system_prompt` parameter is ignored (classifier has no concept of system prompt)
  - inference_time_ms is logged for paper evaluation

Security invariants (inherited from Layer2Analyzer):
  - wrap_untrusted() is called by Layer2Analyzer BEFORE calling judge.call()
  - is_confident() returns False for PARSE_ERROR → escalates to Haiku
  - Any exception during inference → PARSE_ERROR response (fail-open)
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from scanner.layer2_semantic.llm_judge import JudgeResponse

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Confidence threshold below which we escalate to Haiku
_DEFAULT_THRESHOLD = 0.80

# Code-domain detection: compiled once at module load.
# ≥2 independent structural signals required to classify as code domain.
_CODE_PATTERNS = [
    re.compile(r"\bimport\s+\w+", re.MULTILINE),           # import os
    re.compile(r"\bfrom\s+\w[\w.]+\s+import\b"),           # from x import y
    re.compile(r"\bdef\s+\w+\s*\(", re.MULTILINE),         # def func(
    re.compile(r"\bclass\s+\w+[\s(:]", re.MULTILINE),      # class Foo:
    re.compile(r"\bos\.(system|popen|exec)\s*\("),          # os.system(
    re.compile(r"\bsubprocess\s*[\.\(]"),                   # subprocess.run(
    re.compile(r"\bexec\s*\("),                             # exec(
    re.compile(r"\bhttpx?\.(get|post|request)\s*\("),       # requests.post(
    re.compile(r"\bbase64\s*\."),                           # base64.b64decode
    re.compile(r"```python", re.IGNORECASE),                # markdown code block
]
_CODE_DOMAIN_MIN_HITS = 2  # ≥2 independent signals = code domain


class SecuritySLMJudge:
    """
    From-scratch 350M RoPE encoder as a Layer 2 pre-filter.

    The model is lazy-loaded on the first call() to avoid startup overhead
    when --slm-model is not used.

    Args:
        model_path:           Path to the trained SecurityClassifier directory
                              (contains config.json, model_state.pt, tokenizer.json).
        confidence_threshold: Minimum softmax confidence to use local verdict directly
                              without escalating to Haiku (default 0.80).
    """

    def __init__(
        self,
        model_path: str | Path,
        confidence_threshold: float = _DEFAULT_THRESHOLD,
    ) -> None:
        self._model_path = Path(model_path)
        self._threshold = confidence_threshold

        # Lazy-loaded on first call()
        self._model: Any = None
        self._tokenizer: Any = None
        self._torch: Any = None
        self._device: Any = None
        self._max_seq_len: int = 512
        self._pad_id: int = 0

    # ── Public API (same interface as LocalLLMJudge) ──────────────────────────

    def call(self, system_prompt: str, user_message: str) -> JudgeResponse:
        """
        Run one classification pass and return a JudgeResponse.

        The system_prompt argument is ignored — the SLM is a classifier,
        not a text generator.  The user_message content is extracted,
        tokenized, and classified in a single forward pass.

        On any error (model load failure, inference error):
          → returns JudgeResponse(verdict="PARSE_ERROR") which causes
            is_confident() to return False → Haiku escalation.
        """
        try:
            self._ensure_loaded()
            return self._classify(user_message)
        except Exception as exc:
            logger.warning(
                "SecuritySLMJudge: inference failed — will escalate to Haiku. Error: %s", exc
            )
            return JudgeResponse(
                verdict="PARSE_ERROR",
                confidence=0.0,
                attack_types=[],
                findings=[],
                rationale=f"SecuritySLMJudge inference error: {str(exc)[:200]}",
                tokens_used=0,
            )

    def is_confident(self, response: JudgeResponse, input_text: str = "") -> bool:
        """
        Return True if the SLM verdict should be used directly (no Haiku escalation).

        Returns False when:
          - verdict == "PARSE_ERROR" (always escalate on errors)
          - verdict != "CLEAN" (SUSPICIOUS/MALICIOUS always escalate so Haiku can
            confirm true positives or downgrade false positives)
          - input contains Python code patterns (SLM is domain-shifted on code)
          - confidence < threshold (model is uncertain → escalate)
        """
        if response.verdict == "PARSE_ERROR":
            return False
        # Asymmetric gate: only CLEAN verdicts can bypass Haiku.
        # SUSPICIOUS/MALICIOUS escalate so Haiku confirms or downgrades.
        if response.verdict != "CLEAN":
            return False
        # Code-domain guard: SLM trained on advisory prose is unreliable on Python code.
        if input_text and self._is_code_domain(input_text):
            logger.debug("SLMJudge: code-domain input with CLEAN verdict — forcing Haiku escalation")
            return False
        return response.confidence >= self._threshold

    @staticmethod
    def _is_code_domain(text: str) -> bool:
        """Return True if the text contains Python code structural signals.

        A single keyword (e.g. 'subprocess' in a README doc description) is not
        enough — requires ≥2 independent structural pattern hits.
        """
        return sum(1 for p in _CODE_PATTERNS if p.search(text)) >= _CODE_DOMAIN_MIN_HITS

    # ── Model loading ─────────────────────────────────────────────────────────

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        self._load_model()

    def _load_model(self) -> None:
        logger.info("SecuritySLMJudge: loading model from %s ...", self._model_path)

        try:
            import torch
        except ImportError as exc:
            raise ImportError(
                "torch is required for --slm-model. Install with: pip install torch>=2.3"
            ) from exc

        try:
            from tokenizers import Tokenizer
        except ImportError as exc:
            raise ImportError(
                "tokenizers is required for --slm-model. Install with: pip install tokenizers>=0.19"
            ) from exc

        # Import SecurityClassifier from finetuning/model.py via project root
        _project_root = self._model_path.resolve().parent.parent  # typically agentic-scanner/
        # Walk up to find the finetuning/ directory
        for candidate in [
            _project_root,
            self._model_path.resolve().parent.parent.parent,
            Path(__file__).resolve().parent.parent.parent,  # scanner/layer2_semantic/../../
        ]:
            if (candidate / "finetuning" / "model.py").exists():
                _project_root = candidate
                break

        if str(_project_root) not in sys.path:
            sys.path.insert(0, str(_project_root))

        try:
            from finetuning.model import SecurityClassifier
        except ImportError as exc:
            raise ImportError(
                f"Could not import finetuning.model from {_project_root}. "
                "Ensure SecurityClassifier is accessible from the project root."
            ) from exc

        # Select device
        if torch.backends.mps.is_available():
            device = torch.device("mps")
        elif torch.cuda.is_available():
            device = torch.device("cuda")
        else:
            device = torch.device("cpu")
            logger.warning("SecuritySLMJudge: no GPU/MPS found — inference may be slow")

        logger.info("SecuritySLMJudge: device=%s", device)

        # Load the classifier
        use_flash = device.type != "mps"
        model = SecurityClassifier.load(
            self._model_path,
            use_flash_attn=use_flash,
            map_location=str(device),
        )
        model = model.to(device)
        model.eval()

        # Load tokenizer — prefer copy in model dir, fallback to tokenizer_dir param
        tok_path = self._model_path / "tokenizer.json"
        if not tok_path.exists():
            raise FileNotFoundError(
                f"Tokenizer not found at {tok_path}. "
                "train_classifier.py should have copied it there."
            )
        tokenizer = Tokenizer.from_file(str(tok_path))

        # Read special token IDs from config
        import json
        pad_id = 0
        tok_cfg_path = self._model_path / "tokenizer_config.json"
        if tok_cfg_path.exists():
            tok_cfg = json.loads(tok_cfg_path.read_text())
            sp = tok_cfg.get("special_tokens", {})
            pad_id = sp.get("[PAD]", 0)

        max_seq_len = model.config.max_seq_len
        tokenizer.enable_padding(pad_id=pad_id, pad_token="[PAD]", length=max_seq_len)
        tokenizer.enable_truncation(max_length=max_seq_len)

        self._model = model
        self._tokenizer = tokenizer
        self._torch = torch
        self._device = device
        self._max_seq_len = max_seq_len
        self._pad_id = pad_id
        logger.info("SecuritySLMJudge: model loaded successfully")

    # ── Inference ─────────────────────────────────────────────────────────────

    # Attack-type index → T-code mapping (T1=0, T2=1, ... T8=7)
    _ATTACK_TYPE_CODES = ["T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8"]
    _ATTACK_TYPE_THRESHOLD = 0.5  # sigmoid probability above which a type is active

    def _classify(self, user_message: str) -> JudgeResponse:
        """Run one (or chunked) classifier forward pass and return JudgeResponse.

        For inputs that exceed max_seq_len, delegates to _call_chunked() which
        slides a window over the text and aggregates chunk verdicts.
        """
        import time
        t0 = time.perf_counter()

        # Strip <untrusted_content> wrapper if present (added by Layer2Analyzer)
        text = user_message
        if "<untrusted_content>" in text:
            import re
            m = re.search(
                r"<untrusted_content>\s*(.*?)\s*</untrusted_content>",
                text, re.DOTALL
            )
            if m:
                text = m.group(1)

        # Check if text needs chunking (rough token estimate: 4 chars/token)
        estimated_tokens = len(text) // 4
        if estimated_tokens > self._max_seq_len * 0.9:
            return self._call_chunked(text, t0)

        verdict, confidence, attack_type_codes = self._forward_single(text)
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        self._free_cache()

        logger.debug(
            "SecuritySLMJudge: verdict=%s confidence=%.2f inference=%dms",
            verdict, confidence, elapsed_ms,
        )
        return JudgeResponse(
            verdict=verdict,
            confidence=confidence,
            attack_types=attack_type_codes,
            findings=[],
            rationale=f"SLM classifier: {verdict} ({confidence:.0%} confidence, {elapsed_ms}ms)",
            tokens_used=0,
        )

    def _forward_single(self, text: str) -> tuple[str, float, list[str]]:
        """Single forward pass on text. Returns (verdict, confidence, attack_type_codes)."""
        enc = self._tokenizer.encode(text)
        input_ids = self._torch.tensor([enc.ids], dtype=self._torch.long, device=self._device)
        attn_mask = self._torch.tensor([enc.attention_mask], dtype=self._torch.long, device=self._device)

        with self._torch.no_grad():
            verdict_logits, type_logits = self._model(input_ids, attn_mask)
            probs = self._torch.nn.functional.softmax(verdict_logits, dim=-1)  # [1, 3]
            conf, pred = probs.max(dim=-1)

        from finetuning.model import _ID_TO_LABEL
        verdict = _ID_TO_LABEL[pred.item()]
        confidence = conf.item()

        # Decode attack-type predictions via sigmoid threshold
        attack_type_codes: list[str] = []
        if type_logits is not None:
            type_probs = self._torch.sigmoid(type_logits[0])  # [num_attack_types]
            attack_type_codes = [
                self._ATTACK_TYPE_CODES[i]
                for i, p in enumerate(type_probs.tolist())
                if p >= self._ATTACK_TYPE_THRESHOLD and i < len(self._ATTACK_TYPE_CODES)
            ]

        return verdict, confidence, attack_type_codes

    def _call_chunked(self, text: str, t0: float) -> JudgeResponse:
        """Sliding-window inference for inputs exceeding max_seq_len.

        Splits text into overlapping chunks (chunk_size=400 tokens, stride=50),
        classifies each independently, then aggregates:
          verdict     = most severe verdict across all chunks
          confidence  = max confidence across chunks with that verdict
          attack_types = union of all active attack types across chunks
        """
        import time

        # Chunk by approximate word count (conservative: 1 token ≈ 0.75 words)
        words = text.split()
        chunk_words = 300  # ~400 tokens at 0.75 words/token
        stride_words = 40  # ~50 tokens overlap
        chunks = []
        i = 0
        while i < len(words):
            chunk = " ".join(words[i: i + chunk_words])
            chunks.append(chunk)
            if i + chunk_words >= len(words):
                break
            i += stride_words

        if not chunks:
            chunks = [text[:2000]]

        _SEVERITY = {"MALICIOUS": 2, "SUSPICIOUS": 1, "CLEAN": 0}
        best_verdict = "CLEAN"
        best_confidence = 0.0
        all_attack_types: set[str] = set()

        for chunk in chunks:
            verdict, confidence, attack_types = self._forward_single(chunk)
            all_attack_types.update(attack_types)
            if _SEVERITY.get(verdict, 0) > _SEVERITY.get(best_verdict, 0):
                best_verdict = verdict
                best_confidence = confidence
            elif _SEVERITY.get(verdict, 0) == _SEVERITY.get(best_verdict, 0):
                best_confidence = max(best_confidence, confidence)

        self._free_cache()
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        logger.debug(
            "SecuritySLMJudge (chunked): verdict=%s confidence=%.2f chunks=%d inference=%dms",
            best_verdict, best_confidence, len(chunks), elapsed_ms,
        )
        return JudgeResponse(
            verdict=best_verdict,
            confidence=best_confidence,
            attack_types=sorted(all_attack_types),
            findings=[],
            rationale=(
                f"SLM classifier (chunked/{len(chunks)} chunks): "
                f"{best_verdict} ({best_confidence:.0%} confidence, {elapsed_ms}ms)"
            ),
            tokens_used=0,
        )

    def _free_cache(self) -> None:
        """Free GPU/MPS memory cache after inference."""
        import gc
        gc.collect()
        if self._device.type == "mps":
            self._torch.mps.empty_cache()
