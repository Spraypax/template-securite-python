import time
import tp4.main as main


class FakeRemote:
    def __init__(self):
        self.lines = [
            "A décoder: ... --- ...\n".encode(),
            b"GG\n",
        ]
        self.sent = []
        self.closed = False

    def recvline(self, timeout=2):
        if self.lines:
            return self.lines.pop(0)
        return b""

    def sendline(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def test_fast_decode_before_server_closes(monkeypatch):
    fake_io = FakeRemote()

    def fake_remote(host, port):
        return fake_io

    monkeypatch.setattr(main, "remote", fake_remote)

    start = time.perf_counter()
    main.main()
    duration = time.perf_counter() - start

    assert fake_io.sent == [b"sos"]
    assert duration < 0.5
