chmod +x build/linux/build-deb.sh
./build/linux/build-deb.sh

ls -lah build/installer/

sudo apt -f install

sudo dpkg -i "build/installer/android-inspector_1.0.0_amd64.deb"
