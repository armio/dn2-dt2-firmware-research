# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only diagnostic transport. Importing this module opens no MIDI ports.

Extracted from the project's existing MIDI and loader clients; only HELLO and
fixed, caller-allowlisted PEEK requests remain. No firmware/sample payloads.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import fcntl
import hashlib
import struct
import tempfile
import time

PREFIX = bytes.fromhex('f0 00 20 3c 7d 00')
TAG, VERSION = 'os1fs-live-v2', 4


def now():
    return datetime.now(timezone.utc).isoformat()


def require_private_output(path):
    root = Path(__file__).resolve().parents[2]
    if Path(path).resolve().is_relative_to(root):
        raise ValueError('Capture output must be outside the source repository')


def encode7(payload):
    result = bytearray()
    for start in range(0, len(payload), 7):
        group = payload[start:start + 7]
        result.append(sum(((value >> 7) & 1) << (6 - index)
                          for index, value in enumerate(group)))
        result.extend(value & 127 for value in group)
    return bytes(result)

def decode7(payload):
    if any(value > 127 for value in payload):
        raise ValueError('non-MIDI byte in packed payload')
    result = bytearray()
    for start in range(0, len(payload), 8):
        group = payload[start:start + 8]
        if len(group) == 1:
            raise ValueError('packed group has no data')
        for index, value in enumerate(group[1:]):
            result.append(value | (((group[0] >> (6 - index)) & 1) << 7))
    return bytes(result)

def request(sequence, command, arguments=b''):
    return PREFIX + encode7(struct.pack('>HB', sequence, command) + arguments) + b'\xf7'

def parse_reply(message):
    if not message.startswith(PREFIX) or not message.endswith(b'\xf7'):
        return None
    data = decode7(message[len(PREFIX):-1])
    if len(data) < 4:
        raise ValueError('short diagnostic reply')
    sequence, command, status = struct.unpack_from('>HBB', data)
    return sequence, command, status, data[4:]

def decode_peek(reply, address, length):
    if len(reply) != length + 4 or struct.unpack_from('>I', reply)[0] != address:
        raise ValueError(f'unexpected PEEK address or length for 0x{address:08x}/{length}')
    return reply[4:]

def decode_hello(data):
    if len(data) < 7 or b'\0' not in data[6:]:
        raise ValueError('Incomplete HELLO')
    version, frames = struct.unpack_from('>HI', data)
    tag = data[6:].split(b'\0', 1)[0].decode('ascii')
    if (version, tag) != (VERSION, TAG):
        raise ValueError(f'Wrong firmware: {version}/{tag}')
    return dict(protocol=version, tag=tag, frames=frames)

class ReadOnlyClient:
    """One outstanding fixed request; no retries, including read timeouts."""
    def __init__(self, incoming, outgoing, emit, allowed_peeks, clock=time.monotonic, sleep=time.sleep):
        self.incoming, self.outgoing, self.emit = incoming, outgoing, emit
        self.clock, self.sleep = clock, sleep
        self.sequence, self.deadline = 0x600, None
        self.allowed_peeks = frozenset(allowed_peeks)

    def set_deadline(self, deadline):
        self.deadline = deadline

    def call(self, command, arguments=b''):
        if command == 1:
            if arguments:
                raise ValueError('HELLO cannot accept payload')
        elif command == 3:
            if len(arguments) != 6 or struct.unpack('>IH', arguments) not in self.allowed_peeks:
                raise ValueError('PEEK outside fixed diagnostic fields')
        else:
            raise ValueError('Read-only client accepts HELLO/PEEK only')
        if self.deadline is None or self.clock() >= self.deadline:
            raise TimeoutError('Host deadline reached before send')
        self.sequence = self.sequence % 65535 + 1
        packet = request(self.sequence, command, arguments)
        self.emit(dict(event='wire_request', at=now(), command=command, hex=packet.hex()))
        if self.clock() >= self.deadline:
            raise TimeoutError('Host deadline reached while journaling request; nothing sent')
        import mido
        self.outgoing.send(mido.Message.from_bytes(list(packet)))
        expires = min(self.deadline, self.clock()+2)
        while self.clock() < expires:
            for message in self.incoming.iter_pending():
                if self.clock() >= expires:
                    break
                if message.type != 'sysex':
                    continue
                raw = bytes(message.bytes())
                self.emit(dict(event='wire_reply', at=now(), hex=raw.hex()))
                if self.clock() >= expires:
                    raise TimeoutError('Host deadline reached while receiving reply')
                reply = parse_reply(raw)
                if reply and reply[:2] == (self.sequence, command | 0x80):
                    if reply[2]:
                        raise RuntimeError(f'Command {command} refused: status={reply[2]}, snapshot={reply[3].hex()}')
                    return reply[3]
            self.sleep(min(.005, max(0, expires-self.clock())))
        raise TimeoutError(f'No reply to command {command}; request not retried')

def peek(client, address, length):
    return decode_peek(client.call(3, struct.pack('>IH', address, length)), address, length)

@contextmanager
def device(port):
    """Own exact input/output ports; no reset, notes or cleanup messages."""
    import mido
    digest = hashlib.sha256(port.encode()).hexdigest()[:16]
    lock_path = Path(tempfile.gettempdir()) / f'dn2-midi-{digest}.lock'
    with lock_path.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('another DN2 MIDI client owns this output') from exc
        if port not in mido.get_output_names() or port not in mido.get_input_names():
            raise ValueError('exact MIDI input/output port not found')
        with mido.open_output(port) as outgoing, mido.open_input(port) as incoming:
            yield outgoing, incoming
