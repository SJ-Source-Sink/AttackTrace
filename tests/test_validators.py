"""Tests for validator utilities."""

import pytest
from attacktrace.utils.validators import (
    is_valid_domain,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_ip,
    is_valid_cidr,
    is_valid_port,
    is_valid_url,
    sanitize_domain,
    sanitize_ip,
    parse_port_range,
)


class TestDomainValidation:
    def test_valid_domains(self):
        assert is_valid_domain("example.com")
        assert is_valid_domain("sub.example.com")
        assert is_valid_domain("a.b.c.example.com")
        assert is_valid_domain("example-site.com")
        assert is_valid_domain("123.example.com")

    def test_invalid_domains(self):
        assert not is_valid_domain("")
        assert not is_valid_domain("example")
        assert not is_valid_domain("-example.com")
        assert not is_valid_domain("example-.com")
        assert not is_valid_domain("exam ple.com")


class TestIPValidation:
    def test_valid_ipv4(self):
        assert is_valid_ipv4("192.168.1.1")
        assert is_valid_ipv4("10.0.0.1")
        assert is_valid_ipv4("8.8.8.8")
        assert is_valid_ipv4("255.255.255.255")
        assert is_valid_ipv4("0.0.0.0")

    def test_invalid_ipv4(self):
        assert not is_valid_ipv4("256.1.1.1")
        assert not is_valid_ipv4("192.168.1")
        assert not is_valid_ipv4("192.168.1.1.1")
        assert not is_valid_ipv4("abc.def.ghi.jkl")

    def test_valid_ipv6(self):
        assert is_valid_ipv6("::1")
        assert is_valid_ipv6("2001:db8::1")
        assert is_valid_ipv6("fe80::1")

    def test_is_valid_ip(self):
        assert is_valid_ip("192.168.1.1")
        assert is_valid_ip("::1")
        assert not is_valid_ip("invalid")


class TestCIDRValidation:
    def test_valid_cidr(self):
        assert is_valid_cidr("192.168.1.0/24")
        assert is_valid_cidr("10.0.0.0/8")
        assert is_valid_cidr("0.0.0.0/0")

    def test_invalid_cidr(self):
        # Note: bare IPs are valid as /32 networks in Python's ipaddress module
        assert not is_valid_cidr("192.168.1.0/33")
        assert not is_valid_cidr("invalid/24")
        assert not is_valid_cidr("not-an-ip")


class TestPortValidation:
    def test_valid_ports(self):
        assert is_valid_port(1)
        assert is_valid_port(80)
        assert is_valid_port(443)
        assert is_valid_port(65535)

    def test_invalid_ports(self):
        assert not is_valid_port(0)
        assert not is_valid_port(-1)
        assert not is_valid_port(65536)
        assert not is_valid_port("80")


class TestURLValidation:
    def test_valid_urls(self):
        assert is_valid_url("http://example.com")
        assert is_valid_url("https://example.com")
        assert is_valid_url("https://example.com/path")
        assert is_valid_url("http://192.168.1.1")
        assert is_valid_url("http://localhost:8080")

    def test_invalid_urls(self):
        assert not is_valid_url("example.com")
        assert not is_valid_url("ftp://example.com")
        assert not is_valid_url("")


class TestSanitization:
    def test_sanitize_domain(self):
        assert sanitize_domain("EXAMPLE.COM") == "example.com"
        assert sanitize_domain("https://example.com/path") == "example.com"
        assert sanitize_domain("www.example.com") == "example.com"
        assert sanitize_domain("example.com.") == "example.com"
        assert sanitize_domain("invalid") is None

    def test_sanitize_ip(self):
        assert sanitize_ip("192.168.1.1") == "192.168.1.1"
        assert sanitize_ip(" 192.168.1.1 ") == "192.168.1.1"
        assert sanitize_ip("invalid") is None


class TestPortRangeParsing:
    def test_single_port(self):
        assert parse_port_range("80") == [80]

    def test_port_list(self):
        assert parse_port_range("80,443,8080") == [80, 443, 8080]

    def test_port_range(self):
        assert parse_port_range("80-85") == [80, 81, 82, 83, 84, 85]

    def test_mixed(self):
        assert parse_port_range("80,443,8000-8002") == [80, 443, 8000, 8001, 8002]

    def test_invalid(self):
        assert parse_port_range("invalid") == []
        assert parse_port_range("0") == []
        assert parse_port_range("99999") == []
