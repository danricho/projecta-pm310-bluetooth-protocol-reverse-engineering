import asyncio
import struct
from bleak import BleakScanner, BleakClient

async def run():
    print("\nDEVICES")
    devices = await BleakScanner.discover()
    for i, d in enumerate(devices):
        print(f"{i}: {d.name} [{d.address}]")

    MAC_ADDRESS = "CC:8D:A2:74:44:46"

    print(f"\nSERVICES FOR {MAC_ADDRESS}")

    async with BleakClient(MAC_ADDRESS) as client:
        for service in client.services:
            print(f"\n[Service] {service.uuid} (Handle: {service.handle})")
            for char in service.characteristics:
                props = ", ".join(char.properties)
                print(f"  [Characteristic] {char.uuid} — Properties: {props}")
                if "read" in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        print(f"    [Value] {value}")
                    except Exception as e:
                        print(f"    [Read Error] {e}")

        NOTIFY_UUID = "0000c305-0000-1000-8000-00805f9b34fb"

        def handle_notify(_, data):
            
            print("Notification:", data)

        await client.start_notify(NOTIFY_UUID, handle_notify)
        print("\nLISTENING FOR NOTIFICATIONS...")
        await asyncio.sleep(600)  # Listen for x seconds
        await client.stop_notify(NOTIFY_UUID)
    

asyncio.run(run())