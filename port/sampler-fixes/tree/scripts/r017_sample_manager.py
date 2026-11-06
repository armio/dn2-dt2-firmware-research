"""Give both Sample Manager title callers an empty name for an unavailable directory."""


def apply(ctx):
    # The directory accessor already returns its empty string when lookup fails.
    # Send the earlier "model unavailable" branch through that same return.
    ctx.replace(0x47A63DC6, bytes.fromhex('671c'), bytes.fromhex('6714'))
    return dict(directory_name='0x47a63db2', empty_return='0x47a63ddc')
