# v0rtex

IOSurface exploit.

Gets tfp0, works on all devices on 10.3.3 or lower.  
Offsets included only for iPod 6G and and iPhone 5/5c on 10.3.3 though.

### Building

With Xcode:

    make

Without Xcode/macOS you'll at least want to point `IGCC` and `STRIP` to tools that can handle Mach-O's and build for iOS. You might also have to adjust `ARCH` and `IGCC_FLAGS`.

### Write-up

**[Here](https://siguza.github.io/v0rtex/)**.
