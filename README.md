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
- [ ] Snooping the data interface between the LCD/Bluetooth Device (BMD-PT4J) and the core Power Management Device (PM335J)  

## Scripts

To be added.

## Data

To be added.

Both of the scenarios contain the PCAP from the Android HCI Snoop and a screen recording of the tablet for the same period.

### Scenario 1

- When the App was first connected to the PM System via Bluetooth
- Includes app data updates from the system
- Includes commands to the system to toggle states

### Scenario 2

- Includes when the bluetooth of the tablet was cycled on/off.
- Includes app data updates from the system.

