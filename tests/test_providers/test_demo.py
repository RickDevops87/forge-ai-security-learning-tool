import pytest
from src.providers.factory import create_provider


@pytest.mark.asyncio
async def test_demo_provider_returns_response():
    provider = create_provider("demo")
    response = await provider.chat([{"role": "user", "content": "hello"}])
    assert response.content is not None
    assert len(response.content) > 0


@pytest.mark.asyncio
async def test_demo_provider_name():
    provider = create_provider("demo")
    assert "Demo" in provider.name()


@pytest.mark.asyncio
async def test_demo_provider_no_api_key_needed():
    provider = create_provider("demo")
    response = await provider.chat([{"role": "user", "content": "test"}])
    assert response.error is None