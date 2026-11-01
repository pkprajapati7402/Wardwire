"""Tests for Route Normalization and OpenAPI Route Tracking."""

from sentinel.core.route_normalizer import RouteNormalizer


def test_route_normalization_numeric_ids():
    normalizer = RouteNormalizer({"/orders/{id}", "/products/{id}"})
    route, is_doc = normalizer.normalize("/orders/1042")
    assert route == "/orders/{id}"
    assert is_doc is True

    route, is_doc = normalizer.normalize("/products/99")
    assert route == "/products/{id}"
    assert is_doc is True


def test_route_normalization_uuids_and_hex():
    normalizer = RouteNormalizer()
    uuid_str = "c9a646d3-9c61-4cd7-bc15-47044d6fb3f6"
    route, is_doc = normalizer.normalize(f"/v1/payments/{uuid_str}")
    assert route == "/v1/payments/{uuid}"


def test_undocumented_route_flagging():
    documented = {"/products", "/cart", "/checkout"}
    normalizer = RouteNormalizer(documented_routes=documented)

    route1, is_doc1 = normalizer.normalize("/cart")
    assert is_doc1 is True

    route2, is_doc2 = normalizer.normalize("/v0/internal/catalog")
    assert is_doc2 is False

