sudo apt-get install libpcap-dev libssl-dev cmake
wget https://github.com/mfontanini/libtins/archive/master.tar.gz
mv master.tar.gz libtins.tar.gz
tar -xvf libtins.tar.gz
cd "libtins-master"
mkdir -p build
cd build
cmake ../ -DLIBTINS_ENABLE_CXX11=1
sudo make install
sudo ldconfig
