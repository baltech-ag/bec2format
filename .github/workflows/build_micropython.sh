base_path=$1
micropython_version=$2

cd "$base_path" || exit

# install dependencies
sudo apt-get install build-essential libffi-dev git pkg-config

# clone micropython
git clone --branch $micropython_version https://github.com/micropython/micropython
cd micropython || exit

# compile micropython cross compiler
cd mpy-cross || exit
make
cd ..

# compile micropython unix port
cd ports/unix || exit
make submodules
make

# compiled binary is now available at $base_path/ports/unix/build-standard/micropython
