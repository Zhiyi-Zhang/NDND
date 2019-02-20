# Named Data Networking Neighbor Discovery (NDND)

## Authors
* Zhiyi Zhang: zhiyi@cs.ucla.edu
* Xinyu Ma: bitmxy@gmail.com
* Zhaoning Kong: jonnykong@cs.ucla.edu
* Edward Lu: edwardzlu98@gmail.com 

## How NDND works?

There are three participants in NDND protocol.

### ND-Client:
It sends out the query which carries the information of client itself (IP, Netmask, Port, TTL, Timestamp).

### ND-Server:
It processes the query, adds the client information to the local database, collects the information of client’s neighbors (in the same LAN), and then replies.

### Local NFD:
ND-Client manages the local NFD to create new face(s) and new route(s) to the neighbors.

## Try NDND in 3 Steps

### Step 1: Clone the codebase
```
git clone https://github.com/Zhiyi-Zhang/NDND
cd NDND
```

### Step 2: Compile it using “make”
```
make
```

### Step 3: Run it
Server side:
```
./nd-server
```
Client side: 
```
./nd-client [IP] [Optional Port]
```
An client side example: 
```
./nd-client 1.1.1.1 6363
```




### Prerequisite:
* Compile and Install ndn-cxx and NFD.
* Running NFD.


## Future Work

* Add support of Signed Interest after the Signed Interest Format is implemented in ndn-cxx.
* Add Persistent Storage Support.
* Better Scalability of ND-Server

### Long Term:
* Integrate NDND into NDN Control Center