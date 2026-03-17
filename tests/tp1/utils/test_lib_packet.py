import pytest
from unittest.mock import patch
from tp1.utils.lib import proto_name, choose_duration, choose_interface, choose_packet_count, hello_world

@patch("builtins.input", return_value="0")
def test_choose_packet_count_zero(mock_input):
    assert choose_packet_count() == 0
 
@patch("builtins.input", return_value="50")
def test_choose_packet_count_fifty(mock_input):
    assert choose_packet_count() == 50
