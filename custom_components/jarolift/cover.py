"""
Support for Jarolift cover
"""
import logging

import voluptuous as vol

from homeassistant.components.cover import (
    CoverEntityFeature,
#    SUPPORT_SET_TILT_POSITION,
    PLATFORM_SCHEMA,
    CoverDeviceClass,
    CoverEntity
)

from homeassistant.const import CONF_NAME
import homeassistant.helpers.config_validation as cv

CONF_COVERS = "covers"
CONF_GROUP = "group"
CONF_SERIAL = "serial"
CONF_REP_COUNT = "repeat_count"
CONF_REP_DELAY = "repeat_delay"

_COVERS_SCHEMA = vol.All(
    cv.ensure_list,
    [
        vol.Schema(
            {
                vol.Required(CONF_NAME): cv.string,
                vol.Required(CONF_GROUP): cv.string,
                vol.Required(CONF_SERIAL): cv.string,
                vol.Optional(CONF_REP_COUNT, default=0): cv.positive_int,
                vol.Optional(CONF_REP_DELAY, default=0.2): cv.positive_float,
            }
        )
    ],
)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_COVERS): _COVERS_SCHEMA,
    }
)

DEPENDENCIES = ["jarolift"]

_LOGGER = logging.getLogger(__name__)


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    covers_conf = config.get(CONF_COVERS)
    covers = [
        JaroliftCover(
            cover[CONF_NAME],
            cover[CONF_GROUP],
            cover[CONF_SERIAL],
            cover[CONF_REP_COUNT],
            cover[CONF_REP_DELAY],
            hass
        ) for cover in covers_conf
    ]
    async_add_entities(covers)


class JaroliftCover(CoverEntity):
    """Representation a jarolift Cover."""

    def __init__(self, name, group, serial, rep_count, rep_delay, hass):
        """Initialize the jarolift device."""
        self._name = name
        self._group = group
        self._serial = serial
        self._rep_count = rep_count
        self._rep_delay = rep_delay
        self._hass = hass
        self._isClosed = False
        self._position = 50
        supported_features = 0
        #supported_features |= SUPPORT_SET_TILT_POSITION
        supported_features |= CoverEntityFeature.OPEN
        supported_features |= CoverEntityFeature.CLOSE
        supported_features |= CoverEntityFeature.STOP
        self._attr_supported_features = supported_features
        self._attr_device_class = CoverDeviceClass.BLIND
        self._attr_unique_id = "jarolift_" + serial

    @property
    def serial(self):
        """Return the serial of this cover."""
        return self._serial

    @property
    def name(self):
        """Return the name of the cover if any."""
        return self._name

    @property
    def group(self):
        """Return the name of the group if any."""
        return self._group

    @property
    def should_poll(self):
        """No polling available in Jarolift cover."""
        return False

    @property
    def is_closed(self):
        """Return true if cover is closed."""
        return self._isClosed

    @property
    def current_cover_position(self):
        """Return the current position of the cover.
        None is unknown, 0 is closed, 100 is fully open.
        """
        return self._position

    async def async_close_cover(self, **kwargs):
        """Close the cover."""
        self._isClosed = True
        self._position = 0
        await self.async_push_button( "0x2" )

    async def async_open_cover(self, **kwargs):
        """Open the cover."""
        self._isClosed = False
        self._position = 100
        await self.async_push_button( "0x8" )

    async def async_stop_cover(self, **kwargs):
        """Stop the cover."""
        self._isClosed = False
        self._position = 50
        await self.async_push_button( "0x4" )

    async def async_push_button( self, value ):
        await self._hass.services.async_call(
            "jarolift",
            "send_command",
            {"group": self._group, "serial": self._serial, "rep_count": self._rep_count, "rep_delay": self._rep_delay, "button": value},
        )
        self.async_schedule_update_ha_state(True)

#    async def async_set_cover_tilt_position(self, **kwargs):
#        """Drive the cover to tilt position"""
#        await self._hass.services.async_call(
#            "jarolift",
#            "send_command",
#            {
#                "group": self._group,
#                "serial": self._serial,
#                "button": "0x4",
#                "hold": True,
#            },
#        )
