"""
Shared HTTP client with connection pooling for improved performance.

Provides a persistent connection pool that can be reused across modules,
eliminating SSL handshake and connection setup overhead.
"""

import asyncio
from typing import Optional
import httpx


class HTTPClientPool:
    """
    Manages a pool of HTTP clients with connection reuse.

    Usage:
        async with get_client() as client:
            response = await client.get(url)
    """

    _instance: Optional["HTTPClientPool"] = None
    _lock = asyncio.Lock()

    def __init__(self):
        self._client: Optional[httpx.AsyncClient] = None
        self._auth_clients: dict[str, httpx.AsyncClient] = {}

    @classmethod
    async def get_instance(cls) -> "HTTPClientPool":
        """Get singleton instance."""
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    async def get_client(
        self,
        timeout: float = 30.0,
        auth: Optional[tuple[str, str]] = None,
        headers: Optional[dict] = None,
    ) -> httpx.AsyncClient:
        """
        Get an HTTP client from the pool.

        Args:
            timeout: Request timeout in seconds
            auth: Optional (username, password) for basic auth
            headers: Optional default headers

        Returns:
            Configured AsyncClient with connection pooling
        """
        if auth:
            # For authenticated clients, create per-auth-key clients
            auth_key = f"{auth[0]}:{auth[1][:8]}"
            if auth_key not in self._auth_clients:
                self._auth_clients[auth_key] = httpx.AsyncClient(
                    timeout=httpx.Timeout(timeout),
                    limits=httpx.Limits(
                        max_keepalive_connections=50,
                        max_connections=100,
                        keepalive_expiry=30.0,
                    ),
                    auth=auth,
                    headers=headers or {},
                    http2=True,
                    verify=True,
                    follow_redirects=True,
                )
            return self._auth_clients[auth_key]

        # Default client without auth
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(timeout),
                limits=httpx.Limits(
                    max_keepalive_connections=100,
                    max_connections=200,
                    keepalive_expiry=30.0,
                ),
                headers=headers or {},
                http2=True,
                verify=True,
                follow_redirects=True,
            )
        return self._client

    async def close(self):
        """Close all clients in the pool."""
        if self._client:
            await self._client.aclose()
            self._client = None

        for client in self._auth_clients.values():
            await client.aclose()
        self._auth_clients.clear()

    @classmethod
    async def cleanup(cls):
        """Cleanup the singleton instance."""
        if cls._instance:
            await cls._instance.close()
            cls._instance = None


# Convenience function
async def get_http_client(
    timeout: float = 30.0,
    auth: Optional[tuple[str, str]] = None,
    headers: Optional[dict] = None,
) -> httpx.AsyncClient:
    """
    Get a shared HTTP client with connection pooling.

    This client should NOT be closed - it's managed by the pool.

    Args:
        timeout: Request timeout
        auth: Optional basic auth tuple
        headers: Optional default headers

    Returns:
        Shared AsyncClient instance
    """
    pool = await HTTPClientPool.get_instance()
    return await pool.get_client(timeout, auth, headers)


async def cleanup_http_clients():
    """Cleanup all HTTP clients. Call at end of scan."""
    await HTTPClientPool.cleanup()
