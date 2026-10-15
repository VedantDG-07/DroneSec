"""Unit tests for the CoordinateService and geodetic transformation math."""

import math
import pytest

from backend.app.core.coordinate_service import (
    CoordinateService,
    GeographicCoordinates,
    LocalCoordinates,
    DEFAULT_ORIGIN_LATITUDE,
    DEFAULT_ORIGIN_LONGITUDE,
    DEFAULT_ORIGIN_ALTITUDE_MSL,
    MAX_OPERATING_RADIUS_METERS,
)


@pytest.fixture
def default_service() -> CoordinateService:
    return CoordinateService()


@pytest.fixture
def custom_service() -> CoordinateService:
    return CoordinateService(
        origin_latitude=51.5074,
        origin_longitude=-0.1278,
        origin_altitude_msl=25.0,
    )


def test_origin_maps_to_zero_local_displacement(default_service: CoordinateService):
    """The configured origin must map exactly to (0, 0, 0) in local coordinates."""
    origin = default_service.origin
    local = default_service.geographic_to_local(
        origin.latitude, origin.longitude, origin.altitude_msl
    )
    assert local.x == pytest.approx(0.0, abs=1e-9)
    assert local.y == pytest.approx(0.0, abs=1e-9)
    assert local.z == pytest.approx(0.0, abs=1e-9)

    # In reverse: (0, 0, 0) local must map to origin geographic coordinates
    geo = default_service.local_to_geographic(0.0, 0.0, 0.0)
    assert geo.latitude == pytest.approx(origin.latitude, abs=1e-9)
    assert geo.longitude == pytest.approx(origin.longitude, abs=1e-9)
    assert geo.altitude_msl == pytest.approx(origin.altitude_msl, abs=1e-9)


@pytest.mark.parametrize(
    "x, y, z, lat_delta_sign, lon_delta_sign, alt_delta_sign",
    [
        (0.0, 0.0, 100.0, +1, 0, 0),    # Pure North: +Z -> lat increases
        (0.0, 0.0, -100.0, -1, 0, 0),   # Pure South: -Z -> lat decreases
        (100.0, 0.0, 0.0, 0, +1, 0),    # Pure East: +X -> lon increases
        (-100.0, 0.0, 0.0, 0, -1, 0),   # Pure West: -X -> lon decreases
        (0.0, 50.0, 0.0, 0, 0, +1),     # Pure Up: +Y -> alt increases
    ],
)
def test_directional_movement_signs(
    default_service: CoordinateService,
    x: float,
    y: float,
    z: float,
    lat_delta_sign: int,
    lon_delta_sign: int,
    alt_delta_sign: int,
):
    """Cardinal directions must produce correct sign changes in geodetic coordinates."""
    origin = default_service.origin
    geo = default_service.local_to_geographic(x, y, z)

    if lat_delta_sign > 0:
        assert geo.latitude > origin.latitude
    elif lat_delta_sign < 0:
        assert geo.latitude < origin.latitude
    else:
        assert geo.latitude == pytest.approx(origin.latitude, abs=1e-9)

    if lon_delta_sign > 0:
        assert geo.longitude > origin.longitude
    elif lon_delta_sign < 0:
        assert geo.longitude < origin.longitude
    else:
        assert geo.longitude == pytest.approx(origin.longitude, abs=1e-9)

    if alt_delta_sign > 0:
        assert geo.altitude_msl > origin.altitude_msl
    else:
        assert geo.altitude_msl == pytest.approx(origin.altitude_msl, abs=1e-9)


@pytest.mark.parametrize(
    "x, y, z",
    [
        (0.0, 0.0, 0.0),
        (2.0, 5.0, -2.0),
        (-100.0, 25.0, 100.0),
        (50.0, 50.0, -50.0),
        (1000.0, 100.0, -1500.0),
        (-3000.0, 200.0, 3000.0),
        (4000.0, 0.0, -4000.0),
    ],
)
def test_round_trip_accuracy(default_service: CoordinateService, x: float, y: float, z: float):
    """Local -> Geographic -> Local must preserve coordinates within 1e-6 metres (sub-millimetre)."""
    geo = default_service.local_to_geographic(x, y, z)
    recovered_local = default_service.geographic_to_local(
        geo.latitude, geo.longitude, geo.altitude_msl
    )

    error = math.hypot(recovered_local.x - x, recovered_local.y - y, recovered_local.z - z)
    assert error < 1e-6, f"Round-trip error {error} exceeds 1e-6m for point ({x}, {y}, {z})"


def test_altitude_handling(custom_service: CoordinateService):
    """Nonzero reference altitude must translate directly to local Y displacement."""
    # Origin altitude is 25.0m
    geo = custom_service.local_to_geographic(0.0, 15.0, 0.0)
    assert geo.altitude_msl == pytest.approx(40.0, abs=1e-9)

    local = custom_service.geographic_to_local(51.5074, -0.1278, 50.0)
    assert local.y == pytest.approx(25.0, abs=1e-9)


def test_high_latitude_longitude_scaling():
    """At high latitude (e.g. 60 deg N), cos(60) = 0.5, so 1 metre east gives 2x the delta longitude of equator."""
    service_equator = CoordinateService(origin_latitude=0.0, origin_longitude=0.0)
    service_60deg = CoordinateService(origin_latitude=60.0, origin_longitude=0.0)

    geo_eq = service_equator.local_to_geographic(100.0, 0.0, 0.0)
    geo_60 = service_60deg.local_to_geographic(100.0, 0.0, 0.0)

    delta_lon_eq = geo_eq.longitude - 0.0
    delta_lon_60 = geo_60.longitude - 0.0

    # At 60 degrees, cos(60) = 0.5, delta_lon should be approximately 2 * delta_lon_eq
    assert delta_lon_60 == pytest.approx(2.0 * delta_lon_eq, rel=1e-4)


@pytest.mark.parametrize(
    "invalid_lat, invalid_lon",
    [
        (91.0, 0.0),
        (-90.1, 0.0),
        (0.0, 180.1),
        (0.0, -180.1),
        (float("nan"), 0.0),
        (0.0, float("inf")),
        (float("-inf"), 0.0),
    ],
)
def test_invalid_origin_coordinates(invalid_lat: float, invalid_lon: float):
    """Invalid or non-finite origin coordinates must be rejected."""
    with pytest.raises(ValueError):
        CoordinateService(origin_latitude=invalid_lat, origin_longitude=invalid_lon)


def test_polar_origin_singularity_rejected():
    """Exact poles (-90 and +90) must be rejected because cos(lat)=0 causes division by zero."""
    with pytest.raises(ValueError):
        CoordinateService(origin_latitude=90.0, origin_longitude=0.0)
    with pytest.raises(ValueError):
        CoordinateService(origin_latitude=-90.0, origin_longitude=0.0)


@pytest.mark.parametrize(
    "x, y, z",
    [
        (float("nan"), 0.0, 0.0),
        (0.0, float("inf"), 0.0),
        (0.0, 0.0, float("-inf")),
    ],
)
def test_invalid_local_coordinates_rejected(default_service: CoordinateService, x: float, y: float, z: float):
    """Non-finite local coordinates must be rejected with ValueError."""
    with pytest.raises(ValueError):
        default_service.local_to_geographic(x, y, z)


def test_operating_area_limits(default_service: CoordinateService):
    """Coordinates within 5km radius must be recognized as valid operating area; outside must return False."""
    assert default_service.is_within_operating_area(100.0, 100.0) is True
    assert default_service.is_within_operating_area(3500.0, 3500.0) is True  # ~4949m < 5000m
    assert default_service.is_within_operating_area(4000.0, 4000.0) is False # ~5656m > 5000m
    assert default_service.is_within_operating_area(5000.0, 0.0) is True
    assert default_service.is_within_operating_area(5000.1, 0.0) is False
    assert default_service.is_within_operating_area(float("nan"), 0.0) is False
