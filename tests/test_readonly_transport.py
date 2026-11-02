"""Synthetic diagnostic transport tests; no MIDI package or hardware required."""
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'research/diagnostics'))
import readonly_transport as T


class Message:
    type = 'sysex'

    def __init__(self, raw):
        self.raw = bytes(raw)

    def bytes(self):
        return self.raw

    from_bytes = classmethod(lambda cls, raw: cls(raw))


class Device:
    def __init__(self, fault=None):
        self.time, self.sent, self.pending = 0, [], []
        self.fault = fault

    def clock(self):
        return self.time

    def sleep(self, delay):
        self.time += delay

    def emit(self, event):
        if self.fault == 'journal_deadline' and event['event'] == 'wire_request':
            self.time += 10

    def send(self, message):
        raw = message.bytes()
        self.sent.append(raw)
        if self.fault == 'timeout':
            return
        sequence, command = struct.unpack_from('>HB', T.decode7(raw[len(T.PREFIX):-1]))
        payload = struct.pack('>HI', 4, 123)+T.TAG.encode()+b'\0'
        if command == 3:
            payload = struct.pack('>I', 0x800053a4)+bytes(28)
            if self.fault == 'wrong_address':
                payload = struct.pack('>I', 0x800053a8)+bytes(28)
        reply = struct.pack('>HBB', sequence, command | 128, 0)+payload
        self.pending.append(Message(T.PREFIX+T.encode7(reply)+b'\xf7'))

    def iter_pending(self):
        messages, self.pending = self.pending, []
        return iter(messages)

    def client(self):
        client = T.ReadOnlyClient(self, self, self.emit, {(0x800053a4, 28)}, self.clock, self.sleep)
        client.set_deadline(5)
        return client


class TransportTests(unittest.TestCase):
    def test_hello_and_allowlisted_peek(self):
        dev = Device()
        with patch.dict(sys.modules, {'mido': SimpleNamespace(Message=Message)}):
            client = dev.client()
            self.assertEqual(T.decode_hello(client.call(1))['frames'], 123)
            self.assertEqual(T.peek(client, 0x800053a4, 28), bytes(28))
        self.assertEqual(len(dev.sent), 2)

    def test_write_commands_and_unlisted_reads_never_sent(self):
        dev = Device()
        client = dev.client()
        for command, payload in ((2, b''), (4, b''), (5, b''),
                                 (1, b'payload'), (3, b''),
                                 (3, struct.pack('>IH', 0x800053a4, 29))):
            with self.subTest(command=command, payload=payload), self.assertRaises(ValueError):
                client.call(command, payload)
        self.assertEqual(dev.sent, [])

    def test_deadline_before_send_and_during_journaling(self):
        for fault in (None, 'journal_deadline'):
            dev = Device(fault)
            client = dev.client()
            if fault is None:
                client.set_deadline(0)
            with self.assertRaises(TimeoutError):
                client.call(1)
            self.assertEqual(dev.sent, [])

    def test_timeout_is_bounded_and_never_retried(self):
        dev = Device('timeout')
        with patch.dict(sys.modules, {'mido': SimpleNamespace(Message=Message)}), self.assertRaises(TimeoutError):
            dev.client().call(1)
        self.assertEqual(len(dev.sent), 1)
        self.assertLessEqual(dev.time, 2)

    def test_wrong_address_reply_rejected(self):
        dev = Device('wrong_address')
        with patch.dict(sys.modules, {'mido': SimpleNamespace(Message=Message)}), self.assertRaises(ValueError):
            T.peek(dev.client(), 0x800053a4, 28)

    def test_wire_boundary_rejects_malformed_payload_and_identity(self):
        for raw in (T.PREFIX+b'\x80\xf7', T.PREFIX+b'\0\xf7', T.PREFIX+T.encode7(b'x')+b'\xf7'):
            with self.assertRaises(ValueError):
                T.parse_reply(raw)
        self.assertIsNone(T.parse_reply(b'unrelated'))
        with self.assertRaises(ValueError):
            T.decode_hello(struct.pack('>HI', 4, 0)+b'wrong\0')
        data = bytes(range(256))
        self.assertEqual(T.decode7(T.encode7(data)), data)

    def test_capture_output_cannot_enter_source_tree(self):
        with self.assertRaises(ValueError):
            T.require_private_output(Path(__file__).resolve().parents[1]/'capture')


if __name__ == '__main__':
    unittest.main()
