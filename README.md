# m5max-touch-firmware

Builds the touch firmware files Linux needs on the 14-inch MacBook Pro with M5 Max (board K114c) from your own macOS restore image. No Apple firmware is in this repository, and the script never downloads any.

You need two members of the macOS 27.3 beta 1 (26C5035r) restore image, from its `Firmware/` folder:

- `K114_Multitouch.im4p` (trackpad and keyboard)
- `K114_KiwiFirmware.im4p` (touch screen)

Run:

```sh
python3 m5max-touch-fw.py -i K114_Multitouch.im4p K114_KiwiFirmware.im4p -o out
sudo cp out/apple/tpmtfw-k114c.bin out/apple/tpkiwifw-k114c.bin /lib/firmware/apple/
```

Python 3 only, no packages. The script prints the size and sha256 of each file it writes.

The touch screen file has three optional operations removed (operations 26, 29 and 30 of the kiwi sequence). They are placeholder writes to address 0, and the driver stops loading at the first one. The script checks that each of the three still has that shape and stops if it does not. Applied to the unmodified blob from the 27.3 beta 1 image (1311454 bytes), the cut gives a 1310315-byte file with sha256 `af4ba3aa50779353c42f8f81e5754cc5ead69a84630cabd34dbaa2df0a6f3661`, the file the working boot uses.

The drivers are `hid-apple-mtp-kiwi` ([aurora-silicon/linux #1605](https://github.com/aurora-silicon/linux/pull/1605)) and the dockchannel HID driver. The boot files are in the [release of the K114c kernel](https://github.com/joshuaswarren/linux/releases/tag/m5max-k114c-t3hk5y-20261111).

MIT license. The trackpad serializer is adapted from the MIT-licensed `asahi_firmware` module.
