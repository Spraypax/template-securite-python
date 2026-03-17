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

def test_sort_network_protocols(capture):
    capture.protocol_counter["TCP"] = 10
    capture.protocol_counter["UDP"] = 5
    sorted_p = capture.sort_network_protocols()
    assert list(sorted_p.keys())[0] == "TCP"
 
def test_get_summary_after_analyse(capture):
    capture.protocol_counter["TCP"] = 3
    capture.analyse()
    assert "TCP" in capture.get_summary()
