from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import CONF_HOST, CONF_PORT
from tests.common import MockConfigEntry

DOMAIN = "quickbars"


@pytest.fixture
def mock_bus_unsub(hass: HomeAssistant):
    """Patch hass.bus.async_listen to return a callable we can assert on."""
    unsub = MagicMock()
    with patch.object(hass.bus, "async_listen", return_value=unsub):
        yield unsub


@pytest.fixture
def patch_ws_ping():
    """Mock ws_ping used by the coordinator so setup succeeds without network."""
    with patch(
        "homeassistant.components.quickbars.__init__.ws_ping",
        AsyncMock(return_value=True),
    ):
        yield


@pytest.fixture
def patch_zeroconf_browser():
    """
    Avoid real Zeroconf network activity by patching AsyncServiceBrowser and
    async_get_async_instance so Presence.start()/stop() is a no-op.
    """
    class _DummyBrowser:
        async def async_cancel(self):
            return None

    dummy_aiozc = type("AioZC", (), {"zeroconf": object(), "async_get_service_info": AsyncMock(return_value=None)})

    with patch(
        "homeassistant.components.quickbars.__init__.AsyncServiceBrowser",
        return_value=_DummyBrowser(),
    ), patch(
        "homeassistant.components.quickbars.__init__.ha_zc.async_get_async_instance",
        AsyncMock(return_value=dummy_aiozc),
    ):
        yield


@pytest.fixture
def mock_persistent_notification():
    with patch(
        "homeassistant.components.quickbars.__init__.persistent_notification.async_create",
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
    patch_zeroconf_browser,
    mock_bus_unsub,
):
    """Add the entry and set up the integration; return the loaded entry."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()
    assert mock_config_entry.state is ConfigEntryState.LOADED
    return mock_config_entry


# ---------- Config flow client patches ----------

@pytest.fixture
def patch_client_all():
    """
    Patch QuickBarsClient methods used by the flow.

    NOTE: Patch where it's USED: homeassistant.components.quickbars.config_flow.QuickBarsClient
    """
    with patch(
        "homeassistant.components.quickbars.config_flow.QuickBarsClient", autospec=True
    ) as cls:
        inst = cls.return_value
        inst.get_pair_code = AsyncMock(return_value={"sid": "pair-sid-xyz"})
        inst.confirm_pair = AsyncMock(
            return_value={"id": "QB-1234", "name": "QuickBars TV", "port": 9123, "has_token": False}
        )
        inst.set_credentials = AsyncMock(return_value={"ok": True})
        yield inst
