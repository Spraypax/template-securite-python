import os
import pytest
from unittest.mock import patch, MagicMock
 
 
@pytest.fixture
def capture():
    with patch("builtins.input", return_value=""):
        from tp1.utils.capture import Capture
        c = Capture()
        c.protocol_counter["TCP"] = 10
        c.protocol_counter["UDP"] = 5
        c.ip_packet_counter["1.1.1.1"] = 10
        c.ip_proto_counter["1.1.1.1"]["TCP"] = 10
        c.analyse()
        return c

def test_graph_report_creates_file(capture, tmp_path):
    from tp1.utils.report import GraphReport
    path = str(tmp_path / "graph.svg")
    GraphReport(capture).generate(path)
    assert os.path.exists(path)
