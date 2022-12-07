# encio - machine dependent encryption

Package encio provides input/output functions that write encrypted using
AES-256-CFB data.

The encryption key is the machine identifier, unique to the operating 
system.

This makes file non-transferrable between devices.

Encrypted container structure is the following:

```
|__...__|____________...
0  ^   16   ^
   |        +-- encrypted data
   +----------- 16 bytes IV
```
