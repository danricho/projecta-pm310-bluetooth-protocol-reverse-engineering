import pyshark

capture = pyshark.FileCapture(
    '../data/scenario2/BT_HCI.cfa.curf',
    display_filter='btatt',
    include_raw=True,
    use_json=True
)

import struct
import re

def transform_variants(data: bytes, key: bytes):
    """Yield tuples of (label, transformed_data) for different schemes."""
    variants = []

    # XOR
    variants.append(("XOR", bytes(b ^ k for b, k in zip(data, key))))
    # Subtract
    variants.append(("SUB", bytes((b - k) % 256 for b, k in zip(data, key))))
    # Add
    variants.append(("ADD", bytes((b + k) % 256 for b, k in zip(data, key))))
    # Reverse bytes
    variants.append(("REVERSE", data[::-1]))
    # Rotate left
    variants.append(("ROT_L", bytes(((b << 1) | (b >> 7)) & 0xFF for b in data)))
    # Rotate right
    variants.append(("ROT_R", bytes(((b >> 1) | (b << 7)) & 0xFF for b in data)))
    # Nibble swap
    variants.append(("SWAP_NIB", bytes(((b & 0x0F) << 4 | (b & 0xF0) >> 4) for b in data)))
    # No transform
    variants.append(("RAW", data))

    return variants

def scan_att_data(att_data, target_range=(0, 100), pin=5297):
    """
    Scan BLE attribute data for:
    - raw/scaled numeric values
    - ASCII matches
    - printable strings
    - BCD
    - nibbles
    - XOR-masked variations using a PIN

    :param att_data: Hex string or bytes of raw attribute data
    :param target_range: Tuple (min, max) or string for ASCII match
    :param formats: Optional struct formats
    :param pin: 4-digit PIN used for XOR unmasking
    :return: List of results
    """
    if isinstance(att_data, str):
        att_data = bytes.fromhex(att_data)

    results = []

    formats = [
        ('B', 1),   # uint8
        ('b', 1),   # int8
        ('H', 2),   # uint16
        ('h', 2),   # int16
        ('I', 4),   # uint32
        ('i', 4),   # int32
        ('Q', 8),   # uint64
        ('q', 8),   # int64
        ('f', 4),   # float32
        ('d', 8),   # float64
    ]

    scales = [1, 1/10, 1/100, 1/1000, 10, 100, 1000, 0.5, 5]
    endians = ['<', '>']

    # Prepare XOR masks derived from the PIN
    pin_variants = [
        pin.to_bytes(2, 'little'),       # 0x52 0x97
        pin.to_bytes(2, 'big'),          # 0x97 0x52
        bytes([int(x) for x in str(pin)]),  # ASCII digits
        struct.pack('<H', pin),
        struct.pack('>H', pin),
    ]

    def decode_numeric(data, label):
        for endianness in endians:
            for fmt, size in formats:
                is_float = fmt in ('f', 'd')
                for offset in range(len(data) - size + 1):
                    chunk = data[offset:offset + size]
                    try:
                        raw = struct.unpack(endianness + fmt, chunk)[0]
                        if is_float:
                            if isinstance(target_range, tuple) and target_range[0] <= raw <= target_range[1]:
                                results.append((offset, endianness, fmt, raw, raw, 1, label))
                        else:
                            for scale in scales:
                                scaled = raw * scale
                                if isinstance(target_range, tuple) and target_range[0] <= scaled <= target_range[1]:
                                    results.append((offset, endianness, fmt, raw, scaled, scale, label))
                    except Exception:
                        continue

    def ascii_search(data, label):
        if isinstance(target_range, str):
            search = target_range.encode('ascii')
            for offset in range(len(data) - len(search) + 1):
                if data[offset:offset + len(search)] == search:
                    results.append((offset, 'ascii', 'str', target_range, label))

    def bcd_decode(data, label):
        def bcd_to_int(byte):
            return ((byte >> 4) * 10) + (byte & 0x0F)

        for offset, byte in enumerate(data):
            val = bcd_to_int(byte)
            if isinstance(target_range, tuple) and target_range[0] <= val <= target_range[1]:
                results.append((offset, 'bcd', 'uint8_bcd', byte, val, label))

    def nibble_decode(data, label):
        for offset, byte in enumerate(data):
            high = (byte >> 4) & 0x0F
            low = byte & 0x0F
            if isinstance(target_range, tuple):
                if target_range[0] <= high <= target_range[1]:
                    results.append((offset, 'nibble', 'high4', high, label))
                if target_range[0] <= low <= target_range[1]:
                    results.append((offset, 'nibble', 'low4', low, label))

    def printable_strings(data, label):
        for match in re.finditer(b'[\x20-\x7E]{4,}', data):
            try:
                s = match.group().decode('ascii')
                results.append((match.start(), 'ascii', 'printable', s, label))
            except Exception:
                continue

    def bits(data, label):
        def extract_bits(byte, start, length):
            mask = (1 << length) - 1
            return (byte >> start) & mask
        for offset, byte in enumerate(att_data):
            for length in range(1, 9):  # Bitfields of width 1 to 8
                for bit_offset in range(0, 8 - length + 1):
                    value = extract_bits(byte, bit_offset, length)
                    for scale in scales:
                        scaled = value * scale                        
                        if target_range[0] <= scaled <= target_range[1]:
                            desc = f'bit{bit_offset}:{bit_offset+length-1}'
                            results.append((offset, 'bit', desc, value, scaled, scale))

    # print(att_data)
    for mask in pin_variants:
        for transform_var in transform_variants(att_data, mask):
            # print(transform_var[1])
            label = f'{transform_var[0]}({mask.hex()})'

            if target_range == "printables":
                printable_strings(transform_var[1], label)
            elif isinstance(transform_var[1], str):
                ascii_search(transform_var[1], label)   
            else:  
                decode_numeric(transform_var[1], label)
                bcd_decode(transform_var[1], label)
                nibble_decode(transform_var[1], label)
                bits(transform_var[1], label)
            


    # Run decoders on raw data
    if target_range == "printables":
        printable_strings(att_data, 'raw')
    elif isinstance(target_range, str):
        ascii_search(att_data, 'raw')
    else:
        decode_numeric(att_data, 'raw')    
        bcd_decode(att_data, 'raw')
        nibble_decode(att_data, 'raw')
        bits(att_data, 'raw')

    return results


import math
from collections import Counter

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())



for pkt in capture:
    
    raw = pkt.get_raw_packet()
    source_mac = pkt.bthci_acl.src.bd_addr

    if not raw:
        continue
    
    if len(raw) < 7:
        continue

    ATT_OFFSET = 7
    att_data = raw[ATT_OFFSET:]
    
    opcode = att_data[0]
    handle = int.from_bytes(att_data[1:3], byteorder='little')
    value = att_data[3:]

    battery_voltage_1 = scan_att_data(value, target_range=(13.375, 13.385))
    battery_voltage_2 = scan_att_data(value, target_range=(13.365, 13.375))
    battery_voltage_3 = scan_att_data(value, target_range=(13.325, 13.335))
    battery_voltage_4 = scan_att_data(value, target_range=(13.305, 13.315))

    # searchedStr = scan_att_data(value, target_range="5297")
    # printables = []
    printables = scan_att_data(value, target_range="printables")    

    if  source_mac == "cc:8d:a2:74:44:46" and (
          len(battery_voltage_1) or \
          len(battery_voltage_2) or \
          len(battery_voltage_3) or \
          len(battery_voltage_4) or \
          len(printables) \
        ):

      print(f"\n=== Packet #{pkt.number} ===")
      print(f"Time: {pkt.sniff_time}")      
      print(f"SRC/DEST: {pkt.bthci_acl.src.name} ({pkt.bthci_acl.src.bd_addr}) -> {pkt.bthci_acl.dst.name} ({pkt.bthci_acl.dst.bd_addr})")

      print(f"Opcode: 0x{opcode:02x}")
      print(f"Handle: 0x{handle:04x}")

      print(f"Length: {pkt.length}")
      print(f"Raw Value: {value.hex()}")    
      
      print(f"Data Entropy Score: {calculate_entropy(value)}\n")  

      # these are based on the voltages observed in the screen recording of data scenario 2
      if len(battery_voltage_1):
        print(f"Found potential (1st) Test Float 13.38 (13.375, 13.385): {battery_voltage_1}")
      if len(battery_voltage_2):
        print(f"Found potential (2nd) Test Float 13.37 (13.365, 13.375): {battery_voltage_2}")
      if len(battery_voltage_3):
        print(f"Found potential (3rd) Test Float 13.33 (13.325, 13.335): {battery_voltage_3}")
      if len(battery_voltage_4):
        print(f"Found potential (4th) Test Float 13.31 (13.305, 13.315): {battery_voltage_4}")

      if len(printables):
        print(f"\nFound printables: {printables}")

      
      

capture.close()