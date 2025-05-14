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

## Scripts

### Setup

```sh
cd scripts
python3 -m venv venv
venv/bin/pip install -r requirements
```

Run a script using `/venv/bin/python xxx.py` command.

Sample outputs for each script are shown next to the python script as .log files.

### discovery.py

Obtains BLE Generic Attribute Profile (GATT) Services and Characteristics as advertised by the Projecta BMD-PT4J.

### dumb_printer.py

Processes packet data using pyshark and allows filtering.

### brute_force_decoding.py

Tries various decoding methods across the data bytes in all packets, printing any possibly successful voltages unpacked.  
Also finds printable strings and displays data entropy on each packet.

This is where some extra checks for LEB128 should be added and tested.

### protocol_reference_strings.py

Contains a large list of strings which was extracted using some decompilation tooling on the Android APK.

