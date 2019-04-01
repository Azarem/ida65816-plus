SNES 65816 Processor Plugin for IDA
===================================

This is a IDA 6.x processor plugin module for SNES 65816 CPU.

**IMPORTANT NOTICE**:
The 65816 processor plugin was forked from [IDA SDK 6.8](https://www.hex-rays.com/products/ida/support/download.shtml),
published by [Hex-Rays](https://www.hex-rays.com/). In IDA 7.0, Hey-Rays has made breaking changes on IDA API design and has been released an [migrating guide](https://www.hex-rays.com/products/ida/7.0/docs/api70_porting_guide.shtml). I don't plan to maintain this project to follow new IDA API design at the moment. I think I will try to make an IDAPython plugin from scratch instead, when I seriously need an extension for SNES reverse engineering, but I really don't need that very soon.

How to compile
--------------

1. Download and install [IDA SDK](https://www.hex-rays.com/products/ida/support/download.shtml) (expected version is IDA SDK 6.9)
2. Clone the repository into $(IDASDK)/module/65816
2. Clone the [snes](https://github.com/gocha/ida-snes-ldr) loader repository for addr.cpp and its dependency
3. Compile the project with [Visual Studio](https://www.visualstudio.com/downloads/download-visual-studio-vs.aspx)

Read official development guides for more details of generic IDA development.
