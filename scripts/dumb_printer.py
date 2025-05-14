import pyshark
from struct import unpack
from typing import Optional

capture = pyshark.FileCapture(
    '../data/scenario2/BT_HCI.cfa.curf',
    display_filter='btatt',
    include_raw=True,
    use_json=True
)


for pkt in capture:
    raw = pkt.get_raw_packet()
    if not raw or len(raw) < 7:
        continue

    source_mac = pkt.bthci_acl.src.bd_addr
    ATT_OFFSET = 7
    att_data = raw[ATT_OFFSET:]
    
    opcode = att_data[0]
    handle = int.from_bytes(att_data[1:3], byteorder='little')
    value = att_data[3:]

    if source_mac == "cc:8d:a2:74:44:46":
        print(f"\n=== Packet #{pkt.number} ===")
        print(f"Time: {pkt.sniff_time}")      
        print(f"SRC/DEST: {pkt.bthci_acl.src.name} ({pkt.bthci_acl.src.bd_addr}) -> {pkt.bthci_acl.dst.name} ({pkt.bthci_acl.dst.bd_addr})")
        print(f"Opcode: 0x{opcode:02x}")
        print(f"Handle: 0x{handle:04x}")
        print(f"Length: {pkt.length}")
        print(f"Raw Value: {value.hex()}")


capture.close()
