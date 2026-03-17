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
def test_pdf_report_creates_file(capture, tmp_path):
    from tp1.utils.report import PdfReport
    path = str(tmp_path / "report.pdf")
    PdfReport(capture, capture.get_summary()).generate(path)
    assert os.path.exists(path)
 
def test_report_generate_array(capture, tmp_path):
    from tp1.utils.report import Report
    r = Report(capture, str(tmp_path / "report.pdf"), capture.get_summary())
    r.generate("array")
    assert os.path.exists("protocol_table.csv")
 
def test_report_save_pdf(capture, tmp_path):
    from tp1.utils.report import Report
    path = str(tmp_path / "report.pdf")
    r = Report(capture, path, capture.get_summary())
    r.save(path)
    assert os.path.exists(path)
