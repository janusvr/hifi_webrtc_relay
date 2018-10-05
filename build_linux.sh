#!/bin/sh

echo -e "\n[*] Installing dependencies"
sudo apt-get install cmake qtcreator qt5-default build-essential libtool m4 automake git libqt5websockets5-dev zlib1g-dev qt5-default qtbase5-private-dev libnice-dev liblog4cxx-dev libssl-dev

git clone https://github.com/sctplab/usrsctp.git
cd usrsctp
./bootstrap
./configure
make
sudo make install
cd ..

echo -e "\n[*] Building librtcdcpp"
cd ./resources/librtcdcpp
rm -rf ./build
mkdir ./build && cd build
cmake .. -DDISABLE_SPDLOG=on
make
cd ..
rm -rf ./lib/linux
mkdir -p ./lib/linux
cp -v ./build/librtcdcpp.so ./lib/linux
cd ../..

BUILD_DIR="dist/linux/"

NPROC=$(nproc)

echo -e "\n[*] Building Hifi WebRTC Relay binary distribution with $NPROC processors. Please wait..."
qmake hifi_webrtc_relay.pro -spec linux-g++ CONFIG+=release CONFIG+=force_debug_info
make clean
make -j$NPROC

# remove previous build attempts in case of failed compilations
echo -e "\n[*] Deleting build dir $BUILD_DIR"
rm -rf $BUILD_DIR

echo -e "\n[*] Creating directory for build distribution in $BUILD_DIR..."
mkdir -p $BUILD_DIR
cp -v hifi_webrtc_relay $BUILD_DIR
cp -v -r resources/librtcdcpp/lib/linux/librtcdcpp.so $BUILD_DIR

echo -e "\n[*] Done! Please run 'hifi_webrtc_relay' from $BUILD_DIR"
