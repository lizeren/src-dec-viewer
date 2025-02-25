# Source-decompiled binary viwer
This tool can be used to compare and view changes between source code and decompiled binary. Each function has features such as:
- Number of parameters
- Stack size of parameters
- Stack size of local variables
- Number of local variables
- etc.
Binary analysis are often interested in those features. src-dec is consisted of two parts: feature extraction of the source code and the decompiled binary.

# How to use

## Prerequisites
**Step 1**: Add LLVM Repository
Ubuntu does not include LLVM 17 by default, so you need to add the official LLVM repository:

```sh
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 17
```
**Step 2**: Install LLVM 17 and Clang 17
Now, install the required packages:
```sh
sudo apt-get install -y llvm-17
sudo apt-get install -y libclang-17-dev
sudo apt-get install -y clang-tools-17
```
**Step 3**: Verify the Installation
Check if the correct versions are installed:
```sh
llvm-config --version
clang --version
clangd --version
```
If the versions are still pointing to older ones, you may need to update the default alternatives:
```sh
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-17 100
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-17 100
sudo update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-17 100
```
**Step 4**:Other dependencies
```sh
sudo apt-get install nlohmann-json3-dev
```
## Build the source analyzer
In the root directory of the project, run the following command to build the source analyzer:
```sh
mkdir build
cd build
cmake ..
make
```
This will create the executable MyStaticAnalyzer in the `build` directory.


## How to analyze source code
To analyze the source code, you need to provide a `compile_commands.json` file. This file captures the compilation commands from the build system. If you are using CMake, you can add the following command to your `CMakeLists.txt` to generate the file:
```sh
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .
```
If you are using Makefile, you can use **bear** to capture the compilation process and generate the file:
```sh
bear -- make -j4
```
Now, you can run the source analyzer by:
```sh
./MyStaticAnalyzer path/to/compile_commands.json

# Example
./MyStaticAnalyzer /mnt/linuxstorage/vlsi-open-source-tool/OpenSTA/build/compile_commands.json
```



