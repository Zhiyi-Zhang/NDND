#!/bin/bash
make_data_dir = "mkdata/"
mkdata = "ndnmkdata"
repo_socket = "localhost 7376"

# make a set of data and insert to repo-ng
#cd $make_data_dir
make clean
make
#cp $mkdata ../
./ndnmkdata -D /repo/A/1 | nc localhost 7376
./ndnmkdata -D /repo/A/2 | nc localhost 7376
./ndnmkdata -D /repo/A/3 | nc localhost 7376
./ndnmkdata -D /repo/A/4 | nc localhost 7376
./ndnmkdata -D /repo/A/5 | nc localhost 7376
./ndnmkdata -D /repo/A/6 | nc localhost 7376
./ndnmkdata -D /repo/A/7 | nc localhost 7376
./ndnmkdata -D /repo/A/8 | nc localhost 7376
./ndnmkdata -D /repo/A/9 | nc localhost 7376
./ndnmkdata -D /repo/A/9/A/B/C | nc localhost 7376
./ndnmkdata -D /repo/A/9/B/A | nc localhost 7376
./ndnmkdata -D /repo/A/9/B/B | nc localhost 7376
# fetch data back from repo-ng
