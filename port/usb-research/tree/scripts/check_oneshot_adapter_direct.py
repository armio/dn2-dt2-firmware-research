"""Read-only emulator helpers used by the exported scratch fixtures.

Extracted from check_oneshot_adapter_direct.py; no capture/firmware loader CLI.
"""


def exact_bytes(dk, state, address, size):
    """Observations must never silently turn missing/symbolic memory into zero."""
    result = bytearray()
    while len(result) < size:
        remaining = size - len(result)
        width = 4 if remaining >= 4 else 2 if remaining >= 2 else 1
        value = dk.st._dm_read(state, address + len(result), width)
        if not isinstance(value, dk.st.Const):
            raise ValueError(f"non-concrete observation at {address + len(result):#x}")
        result.extend((value.value & ((1 << (width * 8)) - 1)).to_bytes(width, "little"))
    return bytes(result)


def register(dk, state, name):
    value = state.uregs.get(dk.st.UREG_CODES[name])
    return value.value if isinstance(value, dk.st.Const) else None
