"""Coordinate conversion service for drone simulation.

Implements flat-earth equirectangular transformations between local Cartesian coordinates (X, Y, Z)
and WGS-84 geodetic coordinates (latitude, longitude, altitude MSL), adhering to the conventions
specified in docs/coordinate-system.md.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


WGS84_EARTH_RADIUS_METERS: float = 6_378_137.0
DEFAULT_ORIGIN_LATITUDE: float = 37.774929
DEFAULT_ORIGIN_LONGITUDE: float = -122.419416
DEFAULT_ORIGIN_ALTITUDE_MSL: float = 15.0
MAX_OPERATING_RADIUS_METERS: float = 5_000.0


@dataclass(frozen=True)
class LocalCoordinates:
    """Local Cartesian coordinate representation in metres.
    
    Attributes:
        x: East-West displacement in metres (+X is East, -X is West).
        y: Vertical altitude above ground/helipad in metres (+Y is Upwards, 0.0 is ground).
        z: North-South displacement in metres (+Z is North, -Z is South).
    """

    x: float
    y: float
    z: float

    def __post_init__(self) -> None:
        if not (math.isfinite(self.x) and math.isfinite(self.y) and math.isfinite(self.z)):
            raise ValueError(f"Local coordinates must be finite real numbers. Got ({self.x}, {self.y}, {self.z})")


@dataclass(frozen=True)
class GeographicCoordinates:
    """WGS-84 geodetic coordinate representation.
    
    Attributes:
        latitude: Geographic latitude in decimal degrees (-90.0 to +90.0).
        longitude: Geographic longitude in decimal degrees (-180.0 to +180.0).
        altitude_msl: Elevation above Mean Sea Level in metres.
    """

    latitude: float
    longitude: float
    altitude_msl: float

    def __post_init__(self) -> None:
        if not (
            math.isfinite(self.latitude)
            and math.isfinite(self.longitude)
            and math.isfinite(self.altitude_msl)
        ):
            raise ValueError(
                f"Geographic coordinates must be finite real numbers. "
                f"Got ({self.latitude}, {self.longitude}, {self.altitude_msl})"
            )
        if not (-90.0 <= self.latitude <= 90.0):
            raise ValueError(f"Latitude must be in [-90.0, 90.0]. Got {self.latitude}")
        if not (-180.0 <= self.longitude <= 180.0):
            raise ValueError(f"Longitude must be in [-180.0, 180.0]. Got {self.longitude}")


class CoordinateService:
    """Service providing bidirectional conversions between local Cartesian coordinates and geodetic coordinates.
    
    Coordinate conventions (right-handed):
        - Local X: positive East, negative West (metres).
        - Local Y: positive Upward altitude (metres, 0.0 at reference ground).
        - Local Z: positive North, negative South (metres).
        - Compass Heading: 0 deg = North (+Z), 90 deg = East (+X), 180 deg = South (-Z), 270 deg = West (-X).
    
    Approximation limits:
        Uses flat-earth equirectangular projection with latitude-scaled longitude.
        Valid for local simulation areas up to 5,000 metres radius from origin.
        Within this operational area, forward and inverse round-trip consistency is < 1e-6 metres.
    """

    def __init__(
        self,
        origin_latitude: float = DEFAULT_ORIGIN_LATITUDE,
        origin_longitude: float = DEFAULT_ORIGIN_LONGITUDE,
        origin_altitude_msl: float = DEFAULT_ORIGIN_ALTITUDE_MSL,
        earth_radius: float = WGS84_EARTH_RADIUS_METERS,
        max_operating_radius: float = MAX_OPERATING_RADIUS_METERS,
    ) -> None:
        if not (
            math.isfinite(origin_latitude)
            and math.isfinite(origin_longitude)
            and math.isfinite(origin_altitude_msl)
            and math.isfinite(earth_radius)
            and math.isfinite(max_operating_radius)
        ):
            raise ValueError("All origin parameters must be finite real numbers.")

        if not (-90.0 < origin_latitude < 90.0):
            raise ValueError(
                f"Origin latitude must be strictly within (-90.0, 90.0) to avoid polar singularities. "
                f"Got {origin_latitude}"
            )
        if not (-180.0 <= origin_longitude <= 180.0):
            raise ValueError(f"Origin longitude must be in [-180.0, 180.0]. Got {origin_longitude}")
        if earth_radius <= 0.0:
            raise ValueError(f"Earth radius must be positive. Got {earth_radius}")
        if max_operating_radius <= 0.0:
            raise ValueError(f"Max operating radius must be positive. Got {max_operating_radius}")

        self._origin_lat = float(origin_latitude)
        self._origin_lon = float(origin_longitude)
        self._origin_alt = float(origin_altitude_msl)
        self._earth_radius = float(earth_radius)
        self._max_operating_radius = float(max_operating_radius)

        # Precompute cosine of origin latitude for longitude scaling
        self._cos_origin_lat = math.cos(math.radians(self._origin_lat))

    @property
    def origin(self) -> GeographicCoordinates:
        """Return the configured geographic origin."""
        return GeographicCoordinates(
            latitude=self._origin_lat,
            longitude=self._origin_lon,
            altitude_msl=self._origin_alt,
        )

    @property
    def max_operating_radius(self) -> float:
        """Return maximum supported horizontal radius in metres."""
        return self._max_operating_radius

    def is_within_operating_area(self, x: float, z: float) -> bool:
        """Check if local horizontal displacement is within the supported 5km operational radius."""
        if not (math.isfinite(x) and math.isfinite(z)):
            return False
        displacement_radius = math.hypot(x, z)
        return displacement_radius <= self._max_operating_radius

    def local_to_geographic(self, x: float, y: float, z: float) -> GeographicCoordinates:
        """Convert local Cartesian coordinates (x, y, z) in metres to WGS-84 geographic coordinates.
        
        Equations:
            Delta_lat (rad) = z / R
            Delta_lon (rad) = x / (R * cos(origin_lat))
            lat = origin_lat + Delta_lat * (180 / pi)
            lon = origin_lon + Delta_lon * (180 / pi)
            alt_msl = origin_alt + y
        """
        if not (math.isfinite(x) and math.isfinite(y) and math.isfinite(z)):
            raise ValueError(f"Local coordinates must be finite real numbers. Got x={x}, y={y}, z={z}")

        # Compute latitude and longitude offsets
        delta_lat_rad = z / self._earth_radius
        delta_lon_rad = x / (self._earth_radius * self._cos_origin_lat)

        latitude = self._origin_lat + math.degrees(delta_lat_rad)
        longitude = self._origin_lon + math.degrees(delta_lon_rad)
        altitude_msl = self._origin_alt + y

        # Normalize longitude into [-180, 180]
        longitude = ((longitude + 180.0) % 360.0) - 180.0

        return GeographicCoordinates(
            latitude=latitude,
            longitude=longitude,
            altitude_msl=altitude_msl,
        )

    def geographic_to_local(
        self, latitude: float, longitude: float, altitude_msl: float
    ) -> LocalCoordinates:
        """Convert WGS-84 geographic coordinates to local Cartesian coordinates (x, y, z) in metres.
        
        Equations:
            z = (latitude - origin_lat) * (pi / 180) * R
            x = (longitude - origin_lon) * (pi / 180) * R * cos(origin_lat)
            y = altitude_msl - origin_alt
        """
        if not (math.isfinite(latitude) and math.isfinite(longitude) and math.isfinite(altitude_msl)):
            raise ValueError(
                f"Geographic coordinates must be finite real numbers. "
                f"Got lat={latitude}, lon={longitude}, alt={altitude_msl}"
            )
        if not (-90.0 <= latitude <= 90.0):
            raise ValueError(f"Latitude must be in [-90.0, 90.0]. Got {latitude}")
        if not (-180.0 <= longitude <= 180.0):
            raise ValueError(f"Longitude must be in [-180.0, 180.0]. Got {longitude}")

        delta_lat_deg = latitude - self._origin_lat
        
        # Calculate shortest angular delta for longitude taking wrap-around into account
        delta_lon_deg = (longitude - self._origin_lon + 180.0) % 360.0 - 180.0

        z = math.radians(delta_lat_deg) * self._earth_radius
        x = math.radians(delta_lon_deg) * self._earth_radius * self._cos_origin_lat
        y = altitude_msl - self._origin_alt

        return LocalCoordinates(x=x, y=y, z=z)
