"""One GUI/handle owner per account; shell requests only request authentication."""
import hashlib
import json

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket

MAX_REQUEST_BYTES = 16384
ALLOWED_ACTIONS = {'show', 'open-face', 'open-pin', 'protect', 'lock'}


def instance_name(data_directory):
    identity = str(data_directory).casefold().encode('utf-8')
    return 'FaceGate-' + hashlib.sha256(identity).hexdigest()[:32]


def valid_request(value):
    if not isinstance(value, dict) or value.get('action') not in ALLOWED_ACTIONS:
        return False
    path = value.get('path', '')
    return isinstance(path, str) and '\x00' not in path and (value['action'] == 'show' or bool(path))


def forward_request(name, request):
    if not valid_request(request):
        raise ValueError('Invalid FaceGate request')
    payload = json.dumps(request, ensure_ascii=True).encode('utf-8') + b'\n'
    if len(payload) > MAX_REQUEST_BYTES:
        raise ValueError('Folder path is too long')
    sock = QLocalSocket()
    sock.connectToServer(name)
    if not sock.waitForConnected(400):
        return False
    try:
        if sock.write(payload) != len(payload):
            raise RuntimeError('ارسال درخواست به FaceGate انجام نشد.')
        if sock.bytesToWrite() and not sock.waitForBytesWritten(1000):
            raise RuntimeError('درخواست به FaceGate نرسید؛ دوباره تلاش کن.')
        return True
    finally:
        sock.disconnectFromServer()


class InstanceServer(QObject):
    request_received = Signal(dict)

    def __init__(self, name, parent=None):
        super().__init__(parent)
        self._connections = set()
        self.server = QLocalServer(self)
        self.server.setSocketOptions(QLocalServer.UserAccessOption)
        self.server.newConnection.connect(self._accept)
        # Never unlink a pipe/socket owned by a potentially live instance.
        if not self.server.listen(name):
            raise RuntimeError('کانال محلی FaceGate در دسترس نیست: ' + self.server.errorString())

    def _accept(self):
        while self.server.hasPendingConnections():
            sock = self.server.nextPendingConnection()
            self._connections.add(sock)
            buffer = bytearray()
            timer = QTimer(sock)
            timer.setSingleShot(True)
            timer.timeout.connect(lambda sock=sock: sock.abort())
            timer.start(2000)

            def read_request(sock=sock, buffer=buffer, timer=timer):
                buffer.extend(bytes(sock.readAll()))
                if len(buffer) > MAX_REQUEST_BYTES:
                    sock.abort()
                    return
                if b'\n' not in buffer:
                    return
                timer.stop()
                try:
                    request = json.loads(bytes(buffer).split(b'\n', 1)[0])
                except (ValueError, UnicodeError):
                    sock.abort()
                    return
                # One request per connection; no eval, shell commands, or unlock grants.
                sock.readyRead.disconnect()
                sock.disconnectFromServer()
                # A receiver may enter a modal Qt loop. Finish socket work first;
                # it can be deleted during that loop after the sender exits.
                if valid_request(request):
                    self.request_received.emit(request)

            sock.readyRead.connect(read_request)
            def disconnected(sock=sock):
                self._connections.discard(sock)
                sock.deleteLater()

            sock.disconnected.connect(disconnected)
            read_request()
