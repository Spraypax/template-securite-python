import pytest
from unittest.mock import patch
from tp1.utils.lib import proto_name, choose_duration, choose_interface, choose_packet_count, hello_world
 
 
def test_hello_world():
    assert hello_world() == "hello world"
 
def test_proto_name_tcp():
    assert proto_name(6) == "TCP"
 
def test_proto_name_udp():
    assert proto_name(17) == "UDP"
 
def test_proto_name_icmp():
    assert proto_name(1) == "ICMP"
 
def test_proto_name_unknown():
    assert proto_name(99) == "UNKNOWN"
 
def test_proto_name_arp_string():
    assert proto_name("ARP") == "ARP"
