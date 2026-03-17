import pytest
from unittest.mock import patch
from tp1.utils.lib import proto_name, choose_duration, choose_interface, choose_packet_count, hello_world
 
@patch("builtins.input", return_value="eth0")
def test_choose_interface_custom(mock_input):
    assert choose_interface() == "eth0"
