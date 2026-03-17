import pytest
from unittest.mock import patch, MagicMock
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
from scapy.packet import Packet
 
 
@pytest.fixture
def capture():
    with patch("builtins.input", return_value=""):
        from tp1.utils.capture import Capture
        return Capture()
 
def test_handle_ip_increments_protocol(capture):
    pkt = IP(src="1.1.1.1", dst="2.2.2.2", proto=6)
    capture._handle_ip(pkt)
    assert capture.protocol_counter["TCP"] == 1
 
def test_handle_ip_tracks_ips(capture):
    pkt = IP(src="1.1.1.1", dst="2.2.2.2", proto=17)
    capture._handle_ip(pkt)
    assert capture.ip_packet_counter["1.1.1.1"] == 1
    assert capture.ip_packet_counter["2.2.2.2"] == 1
 
def test_handle_arp_increments_protocol(capture):
    pkt = ARP(psrc="1.1.1.1", pdst="2.2.2.2")
    capture._handle_arp(pkt)
    assert capture.protocol_counter["ARP"] == 1
