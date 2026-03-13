import tp4.main as main


class FakeRemote:
    def recvline(self, timeout=2):
        return b""

    def sendline(self, data):
        pass

    def close(self):
        pass


def test_main_connects_to_expected_server(monkeypatch):
    called = {}

    def fake_remote(host, port):
        called["host"] = host
        called["port"] = port
        return FakeRemote()

    monkeypatch.setattr(main, "remote", fake_remote)

    main.main()

    assert called["host"] == "31.220.95.27"
    assert called["port"] == 13337
