# v0rtex

IOSurface exploit.

Gets tfp0, works on A7 through A10 devices on iOS 10.3.3 or lower (offsets not yet included though).

### Building

With Xcode:

    make

Without Xcode/macOS you'll at least want to point `IGCC` and `STRIP` to tools that can handle Mach-O's and build for iOS. You might also have to adjust `ARCH` and `IGCC_FLAGS`.

### Write-up

**[Here](https://siguza.github.io/v0rtex/)**.
