import asyncio
from app.honeypot.ssh_service import SSHHoneypot
from app.honeypot.http_service import HTTPHoneypot
from app.honeypot.ftp_service import FTPHoneypot
from app.honeypot.tcp_service import GenericTCPHoneypot


def test_honeypot_startup_and_shutdown():
    async def _test_lifecycle():
        ssh = SSHHoneypot(port=12222)
        http = HTTPHoneypot(port=18080)
        ftp = FTPHoneypot(port=12121)
        tcp = GenericTCPHoneypot(port=19999)

        await ssh.start()
        assert ssh.is_running is True

        await http.start()
        assert http.is_running is True

        await ftp.start()
        assert ftp.is_running is True

        await tcp.start()
        assert tcp.is_running is True

        await ssh.stop()
        assert ssh.is_running is False

        await http.stop()
        assert http.is_running is False

        await ftp.stop()
        assert ftp.is_running is False

        await tcp.stop()
        assert tcp.is_running is False

    asyncio.run(_test_lifecycle())
