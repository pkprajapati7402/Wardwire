"""Unit and privacy tests for HMAC pseudonymisation."""

from sentinel.core.pseudonym import extract_subnet_prefix, pseudonymize_ip


def test_subnet_prefix_extraction():
    assert extract_subnet_prefix("192.168.1.42") == "192.168.1.0"
    assert extract_subnet_prefix("10.0.5.120") == "10.0.5.0"
    assert extract_subnet_prefix("2001:db8:85a3::8a2e:370:7334") == "2001:db8:85a3::"


def test_pseudonymization_determinism():
    salt = "secret_salt_unit_test"
    ip1 = "203.0.113.195"
    ip2 = "203.0.113.200"

    id1, net1 = pseudonymize_ip(ip1, salt)
    id1_again, net1_again = pseudonymize_ip(ip1, salt)

    # Determinism
    assert id1 == id1_again
    assert net1 == net1_again

    # Subnet grouping: both IPs share the /24 prefix (203.0.113.0)
    id2, net2 = pseudonymize_ip(ip2, salt)
    assert id1 != id2
    assert net1 == net2


def test_privacy_no_raw_ip_leakage():
    salt = "secret_salt_privacy"
    raw_ip = "198.51.100.77"
    ip_id, net_id = pseudonymize_ip(raw_ip, salt)

    # Assert raw IP does not appear in pseudonym IDs
    assert raw_ip not in ip_id
    assert raw_ip not in net_id
    assert ip_id.startswith("ip_")
    assert net_id.startswith("net_")

