from __future__ import annotations

from homeassistant.components.zeroconf import ZeroconfServiceInfo
from homeassistant.config_entries import SOURCE_USER, SOURCE_ZEROCONF
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant

from tests.common import MockConfigEntry

DOMAIN = "quickbars"


async def test_user_flow_pair_then_token_success(hass: HomeAssistant, patch_client_all):
    """User starts flow, enters host:port, code, then token; entry created."""
    # Step 1: open form
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] == "form"
    assert result["step_id"] == "user"

    # Step 2: host/port submitted -> server gives sid, we go to code entry
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={CONF_HOST: "192.0.2.10", CONF_PORT: 9123},
    )
    assert result["type"] == "form"
    assert result["step_id"] == "pair"

    # Step 3: submit code -> flow goes to token (has_token=False)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], user_input={"code": "1234"}
    )
    assert result["type"] == "form"
    assert result["step_id"] == "token"

    # Step 4: submit credentials -> create entry
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], user_input={"url": "http://ha.local:8123", "token": "abc123"}
    )
    assert result["type"] == "create_entry"
    assert result["title"]
    data = result["data"]
    assert data[CONF_HOST] == "192.0.2.10"
    assert data[CONF_PORT] == 9123


async def test_user_flow_already_has_token_skips_token(hass: HomeAssistant, patch_client_all):
    """If confirm_pair returns has_token=True, flow should create entry directly."""
    # Flip the stubbed client to return has_token=True
    patch_client_all.confirm_pair.return_value.update({"has_token": True})

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        user_input={CONF_HOST: "192.0.2.10", CONF_PORT: 9123},
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], user_input={"code": "1234"})

    assert result["type"] == "create_entry"
    data = result["data"]
    assert data[CONF_HOST] == "192.0.2.10"
    assert data[CONF_PORT] == 9123


async def test_zeroconf_discovery_to_confirm(hass: HomeAssistant, patch_client_all):
    """A discovered device should show a confirm form, then proceed to pair."""
    zc = ZeroconfServiceInfo(
        ip_address="192.0.2.20",
        ip_addresses=["192.0.2.20"],
        port=9123,
        hostname="QuickBars-1234.local.",
        type_="_quickbars._tcp.local.",
        name="QuickBars-1234._quickbars._tcp.local.",
        properties={"id": "QB-1234", "api": "1", "app_version": "1.2.3", "name": "QuickBars TV"},
    )

    # Discovery -> confirm form
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF}, data=zc
    )
    assert result["type"] == "form"
    assert result["step_id"] == "zeroconf_confirm"

    # Continue -> pair (get_pair_code called), then token since has_token False by default
    result = await hass.config_entries.flow.async_configure(result["flow_id"], user_input={})
    assert result["type"] == "form"
    assert result["step_id"] == "pair"

    # submit code -> token step
    result = await hass.config_entries.flow.async_configure(result["flow_id"], user_input={"code": "9999"})
    assert result["type"] in {"form", "create_entry"}
    if result["type"] == "form":
        # token step then finish
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input={"url": "http://ha.local:8123", "token": "abc123"}
        )
        assert result["type"] == "create_entry"


async def test_zeroconf_updates_existing_entry(hass: HomeAssistant, patch_client_all):
    """If the device is already configured, zeroconf should update host/port and abort."""
    entry = MockConfigEntry(
        domain=DOMAIN, unique_id="QB-1234", data={CONF_HOST: "192.0.2.10", CONF_PORT: 9123, "id": "QB-1234"}
    )
    entry.add_to_hass(hass)

    zc = ZeroconfServiceInfo(
        ip_address="192.0.2.55",
        ip_addresses=["192.0.2.55"],
        port=9999,
        hostname="QuickBars-1234.local.",
        type_="_quickbars._tcp.local.",
        name="QuickBars-1234._quickbars._tcp.local.",
        properties={"id": "QB-1234", "name": "QuickBars TV"},
    )

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_ZEROCONF}, data=zc
    )
    # The flow should abort because entry already exists; HA Core will update the entry in-place
    assert result["type"] == "abort"
    # Confirm data was updated
    updated = hass.config_entries.async_get_entry(entry.entry_id)
    assert updated.data[CONF_HOST] == "192.0.2.55"
    assert updated.data[CONF_PORT] == 9999
