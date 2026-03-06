"""
finetuning/model.py
───────────────────
Custom 350M-parameter RoPE encoder for security classification.

Architecture (identical for smoke test and full 4090 run):
  - 24 transformer encoder layers with bidirectional self-attention
  - RoPE (rotary position encoding) — no learned position matrix
  - Pre-LayerNorm residuals (more stable for from-scratch training than BERT-style post-LN)
  - Weight-tied MLM head (output embedding = input embedding transposed)
  - 3-class classification head on [CLS] token for downstream fine-tuning

Parameter count (bias=True for FFN, bias=False for QKV/O projections):
  - Token embedding:  32,000 × 1,024         = 32.8M
  - Per layer:        ~12.6M × 24 layers      = 302.4M
  - Total:            ≈ 335M (plan says "~350M" — same architecture as BERT-large)

Provides:
  SecurityEncoderConfig   — dataclass of all hyperparameters; save/load via JSON
  SecurityEncoder         — backbone (embedding + 24 TransformerEncoderLayer + LN)
  SecurityMLMModel        — encoder + MLM head (for pretraining)
  SecurityClassifier      — encoder + 3-class head (for classification fine-tuning)

All models are pure PyTorch — no transformers dependency at inference time.
Save/load via torch.save(state_dict) + JSON config.

Usage:
    from finetuning.model import SecurityEncoderConfig, SecurityClassifier
    config = SecurityEncoderConfig(vocab_size=4000)  # smoke
    model = SecurityClassifier(config)
    model.save(Path("finetuning/security_slm_smoke"))
    loaded = SecurityClassifier.load(Path("finetuning/security_slm_smoke"))
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

import torch
import torch.nn as nn
import torch.nn.functional as F


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass
class SecurityEncoderConfig:
    """All hyperparameters for the 350M RoPE encoder.

    Smoke test:  vocab_size=4000,  max_seq_len=128  (batch=4  on MPS)
    Full run:    vocab_size=32000, max_seq_len=512  (batch=64 on 4090)
    Architecture is IDENTICAL between both runs.
    """
    # Architecture (fixed — identical for smoke and full run)
    n_layers: int = 24
    hidden_dim: int = 1024
    n_heads: int = 16
    intermediate_dim: int = 4096

    # Corpus-dependent (set from trained tokenizer)
    vocab_size: int = 32000
    max_seq_len: int = 512

    # Training regularisation
    dropout: float = 0.1
    layer_norm_eps: float = 1e-12

    # Special token IDs (assigned by train_tokenizer.py — order: PAD CLS SEP UNK MASK)
    pad_token_id: int = 0
    cls_token_id: int = 1
    sep_token_id: int = 2
    unk_token_id: int = 3
    mask_token_id: int = 4

    # Classification
    num_classes: int = 3  # CLEAN=0, SUSPICIOUS=1, MALICIOUS=2

    # Multi-label attack-type head (T1–T8, one sigmoid output per type)
    # Set to 0 to disable the attack-type head (backward-compatible with old checkpoints).
    num_attack_types: int = 8

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "SecurityEncoderConfig":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ── RoPE utilities ────────────────────────────────────────────────────────────

def _precompute_rope_freqs(
    head_dim: int, max_seq_len: int, base: float = 10000.0
) -> tuple[torch.Tensor, torch.Tensor]:
    """Precompute cos/sin tables for RoPE.

    Returns:
        cos, sin — each shape [max_seq_len, head_dim // 2]
    """
    half = head_dim // 2
    inv_freq = 1.0 / (base ** (torch.arange(0, half, dtype=torch.float32) * 2 / head_dim))
    positions = torch.arange(max_seq_len, dtype=torch.float32)
    freqs = torch.outer(positions, inv_freq)  # [max_seq_len, half]
    return freqs.cos(), freqs.sin()


def _apply_rope(
    x: torch.Tensor,
    cos: torch.Tensor,
    sin: torch.Tensor,
) -> torch.Tensor:
    """Apply rotary position embeddings.

    Args:
        x:   [batch, heads, seq_len, head_dim]
        cos: [max_seq_len, head_dim//2]
        sin: [max_seq_len, head_dim//2]

    Returns:
        rotated x with same shape and dtype as input.
    """
    seq_len = x.shape[2]
    # Slice to current sequence length, broadcast over batch + heads
    c = cos[:seq_len].unsqueeze(0).unsqueeze(0)  # [1, 1, seq_len, half]
    s = sin[:seq_len].unsqueeze(0).unsqueeze(0)
    # Cast to x.dtype (float32 on MPS, bfloat16 on CUDA)
    c = c.to(dtype=x.dtype)
    s = s.to(dtype=x.dtype)
    half = x.shape[-1] // 2
    x1, x2 = x[..., :half], x[..., half:]
    return torch.cat([x1 * c - x2 * s, x1 * s + x2 * c], dim=-1)


# ── Multi-head self-attention with RoPE ───────────────────────────────────────

class MultiHeadSelfAttentionRoPE(nn.Module):
    """Bidirectional multi-head self-attention with rotary position encoding.

    Uses torch.nn.functional.scaled_dot_product_attention (PyTorch 2.0+),
    which is memory-efficient on both MPS and CUDA.  When use_flash_attn=False
    (--no-flash-attn on MPS), falls back to explicit matmul to avoid any
    backend-specific SDPA optimisations that might behave differently on MPS.
    """

    def __init__(self, config: SecurityEncoderConfig, use_flash_attn: bool = True) -> None:
        super().__init__()
        assert config.hidden_dim % config.n_heads == 0
        self.n_heads = config.n_heads
        self.head_dim = config.hidden_dim // config.n_heads
        self.hidden_dim = config.hidden_dim
        self.use_flash_attn = use_flash_attn

        # bias=False for Q/K/V (standard RoPE practice; biases add negligible value)
        self.q_proj = nn.Linear(config.hidden_dim, config.hidden_dim, bias=False)
        self.k_proj = nn.Linear(config.hidden_dim, config.hidden_dim, bias=False)
        self.v_proj = nn.Linear(config.hidden_dim, config.hidden_dim, bias=False)
        self.out_proj = nn.Linear(config.hidden_dim, config.hidden_dim, bias=True)
        self.attn_dropout = nn.Dropout(config.dropout)

        # RoPE tables — stored as buffers so .to(device) moves them automatically
        cos, sin = _precompute_rope_freqs(self.head_dim, config.max_seq_len)
        self.register_buffer("rope_cos", cos)  # [max_seq_len, head_dim//2]
        self.register_buffer("rope_sin", sin)

    def forward(
        self,
        x: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        B, L, D = x.shape

        # Project and reshape to [B, heads, L, head_dim]
        Q = self.q_proj(x).view(B, L, self.n_heads, self.head_dim).transpose(1, 2)
        K = self.k_proj(x).view(B, L, self.n_heads, self.head_dim).transpose(1, 2)
        V = self.v_proj(x).view(B, L, self.n_heads, self.head_dim).transpose(1, 2)

        # Apply RoPE to Q and K (not V — standard practice)
        Q = _apply_rope(Q, self.rope_cos, self.rope_sin)
        K = _apply_rope(K, self.rope_cos, self.rope_sin)

        if self.use_flash_attn:
            # PyTorch 2.0+ SDPA — uses memory-efficient attention on CUDA, works on MPS
            additive_mask: Optional[torch.Tensor] = None
            if attention_mask is not None:
                # attention_mask: [B, L], 1=real 0=pad → additive: 0=real -inf=pad
                additive_mask = (1.0 - attention_mask.float()).unsqueeze(1).unsqueeze(2)
                additive_mask = additive_mask * -1e9
                additive_mask = additive_mask.to(dtype=x.dtype)
            dropout_p = self.attn_dropout.p if self.training else 0.0
            out = F.scaled_dot_product_attention(
                Q, K, V,
                attn_mask=additive_mask,
                dropout_p=dropout_p,
                is_causal=False,
            )
        else:
            # Explicit matmul — used with --no-flash-attn on MPS for conservative mode
            scale = self.head_dim ** -0.5
            scores = torch.matmul(Q, K.transpose(-2, -1)) * scale
            if attention_mask is not None:
                additive = (1.0 - attention_mask.float()).unsqueeze(1).unsqueeze(2) * -1e9
                scores = scores + additive.to(dtype=scores.dtype)
            weights = F.softmax(scores, dim=-1)
            weights = self.attn_dropout(weights)
            out = torch.matmul(weights, V)

        # [B, heads, L, head_dim] → [B, L, D]
        out = out.transpose(1, 2).contiguous().view(B, L, D)
        return self.out_proj(out)


# ── Transformer encoder layer ─────────────────────────────────────────────────

class TransformerEncoderLayer(nn.Module):
    """Pre-LayerNorm transformer encoder layer.

    Pre-LN: LayerNorm is applied BEFORE attention/FFN (inside residual branch).
    This is more stable for from-scratch training than BERT's post-LN style.
    Used in GPT-2, LLaMA, Qwen — well-validated for random init training.
    """

    def __init__(self, config: SecurityEncoderConfig, use_flash_attn: bool = True) -> None:
        super().__init__()
        self.attn = MultiHeadSelfAttentionRoPE(config, use_flash_attn=use_flash_attn)
        self.ffn_fc1 = nn.Linear(config.hidden_dim, config.intermediate_dim)
        self.ffn_fc2 = nn.Linear(config.intermediate_dim, config.hidden_dim)
        self.norm1 = nn.LayerNorm(config.hidden_dim, eps=config.layer_norm_eps)
        self.norm2 = nn.LayerNorm(config.hidden_dim, eps=config.layer_norm_eps)
        self.dropout = nn.Dropout(config.dropout)

    def forward(
        self,
        x: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        # Attention sub-layer (pre-LN + residual)
        x = x + self.dropout(self.attn(self.norm1(x), attention_mask))
        # FFN sub-layer (pre-LN + residual)
        ff = self.ffn_fc2(F.gelu(self.ffn_fc1(self.norm2(x))))
        x = x + self.dropout(ff)
        return x


# ── Backbone encoder ──────────────────────────────────────────────────────────

class SecurityEncoder(nn.Module):
    """350M RoPE encoder backbone.

    Random init (std=0.02) — every weight traces to known training data,
    zero external pretrained weights.
    """

    def __init__(self, config: SecurityEncoderConfig, use_flash_attn: bool = True) -> None:
        super().__init__()
        self.config = config
        self.token_embedding = nn.Embedding(
            config.vocab_size, config.hidden_dim, padding_idx=config.pad_token_id
        )
        self.dropout = nn.Dropout(config.dropout)
        self.layers = nn.ModuleList([
            TransformerEncoderLayer(config, use_flash_attn=use_flash_attn)
            for _ in range(config.n_layers)
        ])
        self.final_norm = nn.LayerNorm(config.hidden_dim, eps=config.layer_norm_eps)
        self._init_weights()

    def _init_weights(self) -> None:
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.normal_(module.weight, std=0.02)
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.Embedding):
                nn.init.normal_(module.weight, std=0.02)
                if module.padding_idx is not None:
                    module.weight.data[module.padding_idx].zero_()
            elif isinstance(module, nn.LayerNorm):
                nn.init.ones_(module.weight)
                nn.init.zeros_(module.bias)

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Args:
            input_ids:      [batch, seq_len]
            attention_mask: [batch, seq_len], 1=real token 0=padding (optional)
        Returns:
            hidden_states: [batch, seq_len, hidden_dim]
        """
        x = self.dropout(self.token_embedding(input_ids))
        for layer in self.layers:
            x = layer(x, attention_mask)
        return self.final_norm(x)


# ── MLM model (pretraining) ───────────────────────────────────────────────────

class SecurityMLMModel(nn.Module):
    """Encoder + MLM head for masked language model pretraining.

    MLM head: Dense(hidden→hidden, GELU) → LayerNorm → Linear(hidden→vocab)
    Output embedding is weight-tied to input embedding — saves 33M params and
    improves embedding quality (every MLM gradient also trains token embeddings).
    """

    def __init__(self, config: SecurityEncoderConfig, use_flash_attn: bool = True) -> None:
        super().__init__()
        self.encoder = SecurityEncoder(config, use_flash_attn=use_flash_attn)
        self.config = config

        # MLM head (two-layer: Dense → GELU → LN → projection)
        self.mlm_dense = nn.Linear(config.hidden_dim, config.hidden_dim)
        self.mlm_norm = nn.LayerNorm(config.hidden_dim, eps=config.layer_norm_eps)
        self.mlm_head = nn.Linear(config.hidden_dim, config.vocab_size, bias=False)

        # Weight tying: output projection shares weights with token embedding
        self.mlm_head.weight = self.encoder.token_embedding.weight

        # Init mlm_dense (rest was already init'd by SecurityEncoder._init_weights)
        nn.init.normal_(self.mlm_dense.weight, std=0.02)
        nn.init.zeros_(self.mlm_dense.bias)

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """Returns logits: [batch, seq_len, vocab_size]"""
        hidden = self.encoder(input_ids, attention_mask)
        x = F.gelu(self.mlm_dense(hidden))
        x = self.mlm_norm(x)
        return self.mlm_head(x)

    def save_pretrained(self, output_dir: Path) -> None:
        """Save model for downstream use.

        Saves:
          config.json           — architecture hyperparameters
          model_state.pt        — encoder-only weights (for loading into classifier)
          mlm_model_state.pt    — full MLM model (for resuming pretraining)
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        self.config.save(output_dir / "config.json")

        # Encoder-only state (used by SecurityClassifier.from_pretrained_encoder)
        encoder_state = {
            k[len("encoder."):]: v
            for k, v in self.state_dict().items()
            if k.startswith("encoder.")
        }
        torch.save(encoder_state, output_dir / "model_state.pt")

        # Full MLM state (for resuming pretraining)
        torch.save(self.state_dict(), output_dir / "mlm_model_state.pt")

    @classmethod
    def load_for_resume(cls, output_dir: Path, use_flash_attn: bool = True) -> "SecurityMLMModel":
        """Restore a training checkpoint (full MLM model)."""
        config = SecurityEncoderConfig.load(output_dir / "config.json")
        model = cls(config, use_flash_attn=use_flash_attn)
        state = torch.load(output_dir / "mlm_model_state.pt", map_location="cpu", weights_only=True)
        model.load_state_dict(state)
        return model


# ── Classifier (fine-tuning) ──────────────────────────────────────────────────

_LABEL_MAP: dict[str, int] = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}
_ID_TO_LABEL: dict[int, str] = {v: k for k, v in _LABEL_MAP.items()}


class SecurityClassifier(nn.Module):
    """Encoder + 3-class classification head on the [CLS] token.

    Input:  [CLS] token sequence [SEP]
    Output: logits [batch, 3] → CLEAN / SUSPICIOUS / MALICIOUS

    Inference is a single forward pass — no token generation, no JSON parsing,
    no hallucination risk.  Expected latency: < 10ms on GPU, < 30ms on CPU.
    """

    def __init__(self, config: SecurityEncoderConfig, use_flash_attn: bool = True) -> None:
        super().__init__()
        self.config = config
        self.encoder = SecurityEncoder(config, use_flash_attn=use_flash_attn)
        self.classifier = nn.Linear(config.hidden_dim, config.num_classes)
        nn.init.normal_(self.classifier.weight, std=0.02)
        nn.init.zeros_(self.classifier.bias)

        # Multi-label attack-type head (sigmoid, not softmax — types are not mutually exclusive).
        # Only created when num_attack_types > 0.
        if config.num_attack_types > 0:
            self.attack_type_head: Optional[nn.Linear] = nn.Linear(
                config.hidden_dim, config.num_attack_types
            )
            nn.init.normal_(self.attack_type_head.weight, std=0.02)
            nn.init.zeros_(self.attack_type_head.bias)
        else:
            self.attack_type_head = None

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> tuple[torch.Tensor, Optional[torch.Tensor]]:
        """
        Returns (verdict_logits, attack_type_logits):
          verdict_logits:     [batch, num_classes]   — for CrossEntropy loss
          attack_type_logits: [batch, num_attack_types] | None — for BCE loss (sigmoid)

        [CLS] token is expected at position 0.
        """
        hidden = self.encoder(input_ids, attention_mask)
        cls_repr = hidden[:, 0, :]  # [batch, hidden_dim]
        verdict_logits = self.classifier(cls_repr)
        attack_type_logits = (
            self.attack_type_head(cls_repr) if self.attack_type_head is not None else None
        )
        return verdict_logits, attack_type_logits

    def predict(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
        attack_type_threshold: float = 0.5,
    ) -> tuple[list[str], list[float], list[list[int]]]:
        """Convenience: return (verdict_strings, confidence_floats, attack_type_id_lists).

        attack_type_threshold: sigmoid probability above which an attack type is active.
        Returns attack_type_ids as list of 0-based indices (T1=0 … T8=7).
        """
        with torch.no_grad():
            verdict_logits, type_logits = self.forward(input_ids, attention_mask)
            probs = F.softmax(verdict_logits, dim=-1)
            confs, preds = probs.max(dim=-1)
            if type_logits is not None:
                type_probs = torch.sigmoid(type_logits)  # [batch, num_attack_types]
                type_active = (type_probs >= attack_type_threshold).tolist()
            else:
                type_active = [[]] * input_ids.shape[0]
        verdicts = [_ID_TO_LABEL[p.item()] for p in preds]
        confidences = [c.item() for c in confs]
        attack_types = [
            [i for i, active in enumerate(row) if active]
            for row in type_active
        ]
        return verdicts, confidences, attack_types

    @classmethod
    def from_pretrained_encoder(
        cls,
        encoder_path: Path,
        use_flash_attn: bool = True,
    ) -> "SecurityClassifier":
        """Load encoder weights from a pretraining checkpoint.

        The encoder_path should contain config.json and model_state.pt
        (as saved by SecurityMLMModel.save_pretrained).
        The classifier head is randomly initialised.
        """
        config = SecurityEncoderConfig.load(encoder_path / "config.json")
        model = cls(config, use_flash_attn=use_flash_attn)
        encoder_state = torch.load(
            encoder_path / "model_state.pt", map_location="cpu", weights_only=True
        )
        # Strict=False: classifier head weights not in encoder_state (fresh init is OK)
        model.encoder.load_state_dict(encoder_state, strict=True)
        return model

    def save(self, path: Path) -> None:
        """Save full model (encoder + classifier head + config)."""
        path.mkdir(parents=True, exist_ok=True)
        self.config.save(path / "config.json")
        torch.save(self.state_dict(), path / "model_state.pt")
        # Save label map for reference
        (path / "label_map.json").write_text(
            json.dumps(_LABEL_MAP, indent=2), encoding="utf-8"
        )

    @classmethod
    def load(
        cls,
        path: Path,
        use_flash_attn: bool = True,
        map_location: str = "cpu",
    ) -> "SecurityClassifier":
        """Load a trained classifier from a saved directory."""
        config = SecurityEncoderConfig.load(path / "config.json")
        model = cls(config, use_flash_attn=use_flash_attn)
        state = torch.load(
            path / "model_state.pt", map_location=map_location, weights_only=True
        )
        model.load_state_dict(state)
        return model


# ── Utility: count parameters ─────────────────────────────────────────────────

def count_parameters(model: nn.Module) -> dict[str, int]:
    total = sum(p.numel() for p in model.parameters())
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    return {"total": total, "trainable": trainable}


if __name__ == "__main__":
    # Quick sanity check — print parameter count
    config = SecurityEncoderConfig(vocab_size=32000, max_seq_len=512)
    model = SecurityMLMModel(config, use_flash_attn=False)
    counts = count_parameters(model)
    print(f"MLM model — total: {counts['total']:,} ({counts['total']/1e6:.1f}M)")

    config_smoke = SecurityEncoderConfig(vocab_size=4000, max_seq_len=128)
    clf_smoke = SecurityClassifier(config_smoke, use_flash_attn=False)
    counts_smoke = count_parameters(clf_smoke)
    print(f"Smoke classifier — total: {counts_smoke['total']:,} ({counts_smoke['total']/1e6:.1f}M)")
