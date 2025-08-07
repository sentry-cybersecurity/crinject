"""Base Agent class for all security testing agents."""
# Note: This file should be in security_agents/base.py after renaming
from __future__ import annotations
from abc import ABC, abstractmethod
import httpx


class BaseAgent(ABC):
    """Base class for all security testing agents."""
    
    MAX_ATTEMPTS = 1
    TIMEOUT = httpx.Timeout(15.0, connect=5.0)

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    @abstractmethod
    async def run(self, *args, **kwargs):
        """Execute agent and return JSON-serialisable data."""
        pass