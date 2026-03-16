# MIT License — Copyright (c) 2026 cvemula1
# Base provider interface for NHInsight

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import Identity


class BaseProvider(ABC):
    """Abstract base class for identity providers."""

    name: str = "base"

    def __init__(self, config: NHInsightConfig):
        self.config = config

    @abstractmethod
    def discover(self) -> List[Identity]:
        """Discover all non-human identities from this provider.

        Returns a list of Identity objects with provider-specific metadata.
        Risk analysis and classification happen in separate analyzers.
        """
        ...

    def is_available(self) -> bool:
        """Check if this provider's credentials/access are available."""
        return True
