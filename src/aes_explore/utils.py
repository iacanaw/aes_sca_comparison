"""
Utility functions for byte/state conversions and hex formatting.

AES state is 4x4 bytes in column-major order:
  state[row][col] where row, col in [0..3]

Column-major mapping from 16-byte array:
  byte[0]  -> state[0][0]
  byte[1]  -> state[1][0]
  byte[2]  -> state[2][0]
  byte[3]  -> state[3][0]
  byte[4]  -> state[0][1]
  ...
  byte[15] -> state[3][3]
"""


def bytes_to_state(data: bytes) -> list[list[int]]:
    """
    Convert 16 bytes to 4x4 AES state (column-major).

    Args:
        data: 16 bytes of input

    Returns:
        4x4 list of integers (0-255)
    """
    if len(data) != 16:
        raise ValueError(f"Expected 16 bytes, got {len(data)}")

    state = [[0 for _ in range(4)] for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = data[col * 4 + row]
    return state


def state_to_bytes(state: list[list[int]]) -> bytes:
    """
    Convert 4x4 AES state to 16 bytes (column-major).

    Args:
        state: 4x4 list of integers

    Returns:
        16 bytes
    """
    result = []
    for col in range(4):
        for row in range(4):
            result.append(state[row][col])
    return bytes(result)


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert hex string to bytes.

    Args:
        hex_str: Hex string (32 chars for 16 bytes)

    Returns:
        bytes
    """
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """
    Convert bytes to hex string.

    Args:
        data: bytes

    Returns:
        Lowercase hex string
    """
    return data.hex()


def state_to_hex(state: list[list[int]]) -> str:
    """
    Convert state to hex string (via bytes).
    """
    return bytes_to_hex(state_to_bytes(state))


def hex_to_state(hex_str: str) -> list[list[int]]:
    """
    Convert hex string to state.
    """
    return bytes_to_state(hex_to_bytes(hex_str))


def format_state_grid(state: list[list[int]]) -> str:
    """
    Format state as a readable 4x4 grid.

    Returns multi-line string like:
      2b 28 ab 09
      7e ae f7 cf
      15 d2 15 4f
      16 a6 88 3c
    """
    lines = []
    for row in range(4):
        row_hex = [f"{state[row][col]:02x}" for col in range(4)]
        lines.append("  " + " ".join(row_hex))
    return "\n".join(lines)


def format_state_line(state: list[list[int]]) -> str:
    """
    Format state as single-line hex string.
    """
    return state_to_hex(state)


def format_bytes_grid(data: bytes) -> str:
    """
    Format 16 bytes as a readable 4x4 grid (column-major view).
    """
    return format_state_grid(bytes_to_state(data))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte sequences of equal length.
    """
    if len(a) != len(b):
        raise ValueError(f"Length mismatch: {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


def xor_states(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    """
    XOR two 4x4 states element-wise.
    """
    result = [[0 for _ in range(4)] for _ in range(4)]
    for row in range(4):
        for col in range(4):
            result[row][col] = a[row][col] ^ b[row][col]
    return result


def copy_state(state: list[list[int]]) -> list[list[int]]:
    """
    Deep copy a 4x4 state.
    """
    return [[state[row][col] for col in range(4)] for row in range(4)]
