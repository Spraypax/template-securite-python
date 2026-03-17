import pytest
from unittest.mock import patch
from tp1.utils.lib import proto_name, choose_duration, choose_interface, choose_packet_count, hello_world

@patch("builtins.input", return_value="")
def test_choose_duration_default(mock_input):
    assert choose_duration() == 60
 
@patch("builtins.input", return_value="1h")
def test_choose_duration_hours(mock_input):
    assert choose_duration() == 3600
 
@patch("builtins.input", return_value="30s")
def test_choose_duration_seconds(mock_input):
    assert choose_duration() == 30
