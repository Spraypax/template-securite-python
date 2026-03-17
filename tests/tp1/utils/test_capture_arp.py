import pytest
from unittest.mock import patch
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
from scapy.packet import Packet


@pytest.fixture
def capture():
    with patch("builtins.input", return_value=""):
        from tp1.utils.capture import Capture
        return Capture()

def test_handle_arp_increments_protocol(capture):
    pkt = ARP(psrc="1.1.1.1", pdst="2.2.2.2")
    capture._handle_arp(pkt)
    assert capture.protocol_counter["ARP"] == 1


def test_detect_arp_spoof(capture):
    pkt = ARP(psrc="1.1.1.1", pdst="1.1.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    capture._detect_arp_spoof(pkt)
    assert len(capture.suspicious) == 1
    assert "ARP Spoofing" in capture.suspicious[0]
