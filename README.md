# Reverse Engineering the Projecta PM310 Bluetooth Communications Protocol

Efforts to reverse engineer the bluetooth communications used by the [PM310 IntelliJay 12V Power Management System](https://www.projecta.com.au/ts1721611140/attachments/ProductAttachmentGroup/1/PM310-BT4J%20Instruction%20Manual-IS583%2011-23_Screen.pdf)

## Reversing Avenues

- [x] Obtain BLE Generic Attribute Profile (GATT) Services and Characteristics using Python  
- [x] Snooping the BLE packets (Android HCI Snoop)  
- [x] Decode values from the logged packets (find some known values)  
     - [x] So far, not fruitful  
     - [ ] LEB128 (Dart uses this) remains to be tested  
- [x] Decompiling the [INTELLI-JAY PM210 & 310 Android App](https://play.google.com/store/apps/details?id=com.tbbpower.bwi.cmpj&hl=en_AU)  
     - [x] APK decompilation was successful to the Flutter/Dart interface  
     - [ ] Decompiling the Flutter/Dart VM with Ghidra hasn't been helpful to me so far (the decoding of data appears to be done here)  
- [ ] Snooping the data interface between the LCD/Bluetooth Device (BMD-PT4J) and the core Power Management Device (PM335J) - manual suggests it is RS485.
     - [ ] Could be Modbus?
     - [ ] Hardware ordered! 

## Scripts

MORE TO ADD...

### discovery.py

Obtains BLE Generic Attribute Profile (GATT) Services and Characteristics as advertised by the Projecta BMD-PT4J.

```text
DEVICES
0: PMD_BT4J_cc8da2744446 [CC:8D:A2:74:44:46]

SERVICES FOR CC:8D:A2:74:44:46

[Service] 00001801-0000-1000-8000-00805f9b34fb (Handle: 1)
  [Characteristic] 00002a05-0000-1000-8000-00805f9b34fb — Properties: indicate

[Service] 0000a003-0000-1000-8000-00805f9b34fb (Handle: 64)
  [Characteristic] 0000c400-0000-1000-8000-00805f9b34fb — Properties: read
    [Value] bytearray(b'0')
  [Characteristic] 0000c401-0000-1000-8000-00805f9b34fb — Properties: read
    [Value] bytearray(b'0')

[Service] 0000a002-0000-1000-8000-00805f9b34fb (Handle: 40)
  [Characteristic] 0000c301-0000-1000-8000-00805f9b34fb — Properties: read
    [Value] bytearray(b'\x14.\xca?\x14.\xca?e2e49f537b561da18967ab2933c\n\x88\xa9\xcc?/\x04\x00\x00\x14.\xca?l\xa5\xcc?\x00\x00\x00\x00\xccn\xca?h\xaa\xcc?\x17\x00\x00\x004\x8f\xcb?\x00\x00\x00\x00p\xaa\xcc?\x16\x00\x00\x00h\xaa\xcc?\xff\x03\x00\x00\x14.\xca?\x14.\xca?\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<\xaa\xcc?')    
  [Characteristic] 0000c302-0000-1000-8000-00805f9b34fb — Properties: write
  [Characteristic] 0000c306-0000-1000-8000-00805f9b34fb — Properties: indicate
  [Characteristic] 0000c300-0000-1000-8000-00805f9b34fb — Properties: read
    [Value] bytearray(b'0')
  [Characteristic] 0000c305-0000-1000-8000-00805f9b34fb — Properties: notify
  [Characteristic] 0000c304-0000-1000-8000-00805f9b34fb — Properties: write
  [Characteristic] 0000c303-0000-1000-8000-00805f9b34fb — Properties: write-without-response
  [Characteristic] 0000c307-0000-1000-8000-00805f9b34fb — Properties: read
    [Value] bytearray(b'0')

LISTENING FOR NOTIFICATIONS...
Notification: bytearray(b'\xfe\x00?\x00\x12h#\xa11\x07\xd0\x02\x00\x00\x02h#\xa11\x00\xd6\x00\x00\x00\x0b\x00\x00\x04\x11\x03\x04\x04\x00\x00\xab\x11\x04\x04\x00\x01\x00\xc0\x10\x00\x01\x01\x10\x01\x01\x01\xff\xff\x00\x00\x02\x002\x02\x01\x00\x01&\x01\x01x\xbb\xfe')
```

## Data

Both of the scenarios contain the PCAP from the Android HCI Snoop and a screen recording of the tablet for the same period.

### Scenario 1

[DIRECTORY](data/scenario1/)

- When the App was first connected to the PM System via Bluetooth (requires PIN input)
- Includes app data updates from the system
- Includes commands to the system to toggle states

Some known data (sequential/trends not to a timescale):

```python
battery_voltages = [13.51, 13.46, 13.45, 13.42, 13.44, 13.45, 13.44, 13.43, 13.46, 13.43, 13.45, 13.39, 13.43, 13.47]
battery_SOC = [98]
battery_current = [2.82, 2.79, 2.6, 0.53, 0.0, -1.2, 0.0, 1.84, 0.0, -1.66, 0.0, 2.22]
system_output = [0.0, 2.42, 2.62, 4.21, 2.61, 2.43, 2.41, 2.39, 2.34, 2.99, 2.1, 2.3, 2.52, 3.87]
solar_input = [2.91, 2.88, 2.98, 3.15, 2.85, 2.99, 2.9, 2.87, 2.75, 2.41, 2.34, 2.27, 2.22, 2.25, 2.13, 2.22, 2.16, 2.24, 2.23]
```

### Scenario 2

[DIRECTORY](data/scenario2/)

- Includes when the bluetooth of the tablet was cycled on/off.
- Includes app data updates from the system.

Some known data (sequential/trends not to a timescale):

```python
battery_voltages = [13.38, 13.37, 13.33, 13.31]
battery_SOC = [100]
battery_current = [0.0, -2.74, -2.67]
system_output = [0.0, 2.74, 2.67]
solar_input = [0.0]
```
