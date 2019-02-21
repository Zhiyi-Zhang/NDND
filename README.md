# Named Data Networking Neighbor Discovery (NDND)

## An Overview

Named Data Networking proposes a fundamental change to the Internet’s architecture, moving from a point-to-point to a data-centric model.
NDN can run over layer 2 (WiFi, Bluetooth, etc) or over TCP/UDP/IP.
When running over IP, NDN hosts need a way of automatically discovering and establishing connectivity with each other.
This project provides an implementation of NDN Neighbor Discovery service, which uses a rendezvous server to allow NDN hosts in the same network to discover each other and automatically establish NDN connectivity by creating UDP/IP tunnels among them.

## Authors
* Zhiyi Zhang: zhiyi@cs.ucla.edu
* Xinyu Ma: bitmxy@gmail.com
* Zhaoning Kong: jonnykong@cs.ucla.edu
* Edward Lu: edwardzlu98@gmail.com

We also thank Arthi Padmanabhan (artpad@cs.ucla.edu) for her previous work in NDND.

## How NDND works?

There are three participants in NDND protocol.

#### ND-Client:
It sends out the query which carries the information of client itself (IP, Netmask, Port, TTL, Timestamp).

##### Query Interest
```
Name: /ndn/nd/<parameter digest>
Parameter:
  Parameter-Type (T) Length (L)
  {
    uint8_t V4 // 1 if IPv4, 0 if IPv6
    uint8_t IpAddr[16] // IP address
    uint16_t Port // port number
    uint8_t SubnetMask[16] // netmask
    uint32_t TTL // time to live (millisecond)
    uint64_t TimeStamp // unix time stamp
    Name-TlV // a name TLV
  }
```

#### ND-Server:
It processes the query, adds the client information to the local database, collects the information of client’s neighbors (in the same LAN), and then replies.

##### Data Reply
```
Name: /ndn/nd/<parameter digest>
Content:
  Content-Type (T) Length (L)
  {
    { // item 1
      uint8_t V4 // 1 if IPv4, 0 if IPv6
      uint8_t IpAddr[16] // IP address
      uint16_t Port // port number
      uint8_t SubnetMask[16] // netmask
      Name-TlV // a name TLV
    }
    { // item 2
      ...
    }
    { // item 3
      ...
    }
    ...
  }
Signature:
  SHA-256 Digest Signature
```

#### Local NFD:
ND-Client manages the local NFD to create new face(s) and new route(s) to the neighbors. It uses the NFD Management Protocol (which can be found here https://redmine.named-data.net/projects/nfd/wiki/Management) in order to do the following things: 

##### 1) Create a face for all URI's it receives from the ND-Server by sending a FIB Management control command (a signed interest)

##### Create a route for all URI and prefix pairs it receives from the ND-Server by sending a RIB Management control command (a signed interest)

## Try NDND in 3 Steps

#### Step 1: Clone the codebase
```
git clone https://github.com/Zhiyi-Zhang/NDND
cd NDND
```

#### Step 2: Compile it using “make”
```
make
```

#### Step 3: Run it
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


#### Prerequisite:
* Compile and Install ndn-cxx and NFD.
* Running NFD.


## Future Work

* Add support of Signed Interest after the Signed Interest Format is implemented in ndn-cxx.
* Add Persistent Storage Support.
* Better Scalability of ND-Server

### Long Term:
* Integrate NDND into NDN Control Center
