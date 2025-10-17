"""Fixtures for QuickBars integration tests.

Patches zeroconf/network and persistent notifications to avoid real I/O.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, Mock, patch

import pytest

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant

from tests.common import MockConfigEntry

DOMAIN = "quickbars"

@pytest.fixture
def mock_bus_unsub(hass: HomeAssistant):
    """Mock the EventBus listener unsubscription used by the integration."""
    unsub = Mock(name="unsub")

    def fake_async_listen(self, event_type, callback):
        return unsub

    with patch("homeassistant.core.EventBus.async_listen", new=fake_async_listen):
        yield unsub

@pytest.fixture
def patch_ws_ping():
    """Mock ws_ping used by the coordinator so setup succeeds without network."""
    with patch(
        "homeassistant.components.quickbars.coordinator.ws_ping",
        AsyncMock(return_value=True),
    ):
        yield

@pytest.fixture(autouse=True)
def patch_zeroconf():
    """Prevent real zeroconf I/O and satisfy code paths in __init__."""

    class _DummyAsyncZC:
        def __init__(self) -> None:
            self.zeroconf = object()

        async def async_close(self):
            pass

        async def async_get_service_info(self, *args, **kwargs):
            return None

    async def _fake_get_async_instance(_hass):
        return _DummyAsyncZC()

    class _DummyBrowser:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def async_cancel(self):
            pass

    with (
        patch(
            "homeassistant.components.quickbars.ha_zc.async_get_async_instance",
            side_effect=_fake_get_async_instance,
        ),
        patch(
            "homeassistant.components.quickbars.AsyncServiceBrowser",
            new=_DummyBrowser,
        ),
    ):
        yield

@pytest.fixture
def mock_persistent_notification():
    """Patch persistent_notification.async_create used by the integration."""
    with patch(
        "homeassistant.components.quickbars.persistent_notification.async_create",
        autospec=True,
    ) as m:
        yield m

@pytest.fixture
def mock_config_entry() -> MockConfigEntry:
    """Minimal entry data your integration expects."""
    return MockConfigEntry(
        domain=DOMAIN,
        title="QuickBars TV",
        unique_id="QB-1234",
        data={CONF_HOST: "192.0.2.10", CONF_PORT: 9123, "id": "QB-1234"},
    )

@pytest.fixture
async def setup_integration(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    patch_ws_ping,
    mock_bus_unsub,
):
    """Add the entry and set up the integration; return the loaded entry."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    assert mock_config_entry.state is ConfigEntryState.LOADED
    return mock_config_entry

@pytest.fixture
def patch_client_all():
    """Patch QuickBarsClient methods used by the flow.

    NOTE: Patch where it's USED:
    homeassistant.components.quickbars.config_flow.QuickBarsClient
    """
    with patch(
        "homeassistant.components.quickbars.config_flow.QuickBarsClient", autospec=True
    ) as cls:
        inst = cls.return_value
        inst.get_pair_code = AsyncMock(return_value={"sid": "pair-sid-xyz"})
        inst.confirm_pair = AsyncMock(
            return_value={
                "id": "QB-1234",
                "name": "QuickBars TV",
                "port": 9123,
                "has_token": False,
            }
        )
        inst.set_credentials = AsyncMock(return_value={"ok": True})
        yield inst
