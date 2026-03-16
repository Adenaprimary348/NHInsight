# MIT License — Copyright (c) 2026 cvemula1
# LLM-powered explanation layer for NHInsight findings

from __future__ import annotations

import logging
from typing import Optional

from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import Identity

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a cloud security expert. You explain non-human identity "
    "risks to DevOps engineers in clear, actionable language. Be concise (3-4 sentences). "
    "Always include: what the risk is, why it matters, and a specific fix."
)


def explain_finding(identity: Identity, config: NHInsightConfig) -> Optional[str]:
    """Generate a plain-English explanation for an identity's risk flags using an LLM.

    Returns None if no API key is configured or if the identity has no risk flags.
    """
    if not config.openai_api_key:
        return None

    if not identity.risk_flags:
        return None

    try:
        import openai

        client = openai.OpenAI(api_key=config.openai_api_key)

        risk_summary = "\n".join(
            f"- [{f.severity.value}] {f.message}: {f.detail}"
            for f in identity.risk_flags
        )

        prompt = f"""Explain the following non-human identity risk to a DevOps engineer.

Identity: {identity.name}
Type: {identity.identity_type.value}
Provider: {identity.provider.value}
Classification: {identity.classification.value}
Age: {identity.age_days or 'unknown'} days
Last used: {identity.days_since_last_used or 'unknown'} days ago
Policies: {', '.join(identity.policies[:10]) or 'none listed'}

Risk flags:
{risk_summary}

Give a concise explanation (3-4 sentences) covering:
1. What the risk is in plain terms
2. What could go wrong (realistic attack scenario)
3. Specific fix (exact commands or steps)"""

        response = client.chat.completions.create(
            model=config.openai_model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            max_tokens=250,
            temperature=0.3,
        )
        return response.choices[0].message.content.strip()

    except ImportError:
        logger.warning("openai package not installed. Run: pip install openai")
        return None
    except Exception as e:
        logger.warning("LLM explanation failed: %s", e)
        return None
