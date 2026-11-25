"""Drives mailer.send through real smtplib and TLS against a local test server."""

import shutil
import socketserver
import ssl
import subprocess
import threading
from dataclasses import replace
from email import message_from_bytes, policy

import pytest

from snitch import config, mailer

pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")


class SmtpHandler(socketserver.StreamRequestHandler):
    def _say(self, text):
        self.wfile.write(text.encode() + b"\r\n")
        self.wfile.flush()

    def _rebind(self, connection):
        self.request = connection
        self.rfile = connection.makefile("rb")
        self.wfile = connection.makefile("wb")

    def handle(self):
        server = self.server
        if server.implicit_tls:
            self._rebind(server.tls.wrap_socket(self.request, server_side=True))
        self._say("220 test ready")
        encrypted = server.implicit_tls
        while line := self.rfile.readline():
            command = line.decode().strip()
            verb = command.split(" ")[0].upper()
            if verb == "EHLO":
                self.wfile.write(b"250-test\r\n")
                if not encrypted:
                    self.wfile.write(b"250-STARTTLS\r\n")
                self._say("250 AUTH PLAIN")
            elif verb == "STARTTLS":
                self._say("220 go ahead")
                self._rebind(server.tls.wrap_socket(self.request, server_side=True))
                encrypted = True
            elif verb == "AUTH":
                server.log.append(("auth_encrypted", encrypted))
                self._say("235 ok")
            elif verb == "MAIL":
                server.log.append(("from", command))
                self._say("250 ok")
            elif verb == "RCPT":
                server.log.append(("rcpt", command))
                self._say("250 ok")
            elif verb == "DATA":
                self._say("354 send")
                data = b""
                while (chunk := self.rfile.readline()) != b".\r\n":
                    data += chunk
                server.log.append(("data", data))
                self._say("250 ok")
            elif verb == "QUIT":
                self._say("221 bye")
                return
            else:
                self._say("502 no")


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    directory = tmp_path_factory.mktemp("tls")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", key, "-out", cert, "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def start_server(certificate, implicit_tls):
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(*certificate)
    server = socketserver.ThreadingTCPServer(("localhost", 0), SmtpHandler)
    server.daemon_threads = True
    server.handle_error = lambda *args: None  # Refused TLS handshakes are expected here.
    server.tls, server.log, server.implicit_tls = tls, [], implicit_tls
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture(params=[("starttls", False), ("ssl", True)], ids=["starttls", "ssl"])
def relay(request, certificate):
    security, implicit = request.param
    server = start_server(certificate, implicit)
    yield security, server
    server.shutdown()
    server.server_close()


def make_config(security, port):
    return replace(
        config.load({}),
        smtp_host="localhost",
        smtp_port=port,
        smtp_security=security,
        smtp_user="resend",
        smtp_password="key",
        mail_from="reports@example.net",
    )


def test_message_is_delivered_over_tls_with_login(relay, certificate, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate[0]))
    security, server = relay
    cfg = make_config(security, server.server_address[1])
    message = mailer.new_message(cfg, ["abuse@host.example"], "Subject line", "Body\n")
    message.add_attachment("evidence\n", subtype="plain", filename="e.txt", cte="base64")

    mailer.send(cfg, mailer.parse(message.as_bytes()))

    log = dict(server.log)
    assert log["auth_encrypted"] is True
    assert "reports@example.net" in log["from"]
    assert "abuse@host.example" in log["rcpt"]
    delivered = message_from_bytes(log["data"], policy=policy.default)
    assert delivered["Subject"] == "Subject line"
    assert next(delivered.iter_attachments()).get_content() == "evidence\n"


def test_untrusted_certificate_is_refused_before_credentials_are_sent(relay, tmp_path, monkeypatch):
    other = tmp_path / "empty.pem"
    other.write_text("")
    monkeypatch.setenv("SSL_CERT_FILE", str(other))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    security, server = relay
    cfg = make_config(security, server.server_address[1])
    message = mailer.new_message(cfg, ["abuse@host.example"], "s", "b\n")
    with pytest.raises(ssl.SSLError):
        mailer.send(cfg, message)
    assert not any(kind == "auth_encrypted" for kind, _ in server.log)
