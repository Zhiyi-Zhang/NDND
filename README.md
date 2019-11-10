# Named Data Networking Neighbor Discovery (NDND)

## An Overview

Named Data Networking proposes a fundamental change to the Internet’s architecture, moving from a point-to-point to a data-centric model.
NDN can run over layer 2 (WiFi, Bluetooth, etc) or over TCP/UDP/IP.
When running over IP, NDN hosts need a way of automatically discovering and establishing connectivity with each other.
This project provides an implementation of NDN Neighbor Discovery service, which uses a rendezvous server to allow NDN hosts in the same network to discover each other and automatically establish NDN connectivity by creating UDP/IP tunnels among them.

## Authors
* Zhiyi Zhang: zhiyi@cs.ucla.edu
* Xinyu Ma: bitmxy@gmail.com
* Tianyuan Yu: tianyuan@cs.ucla.com
* Zhaoning Kong: jonnykong@cs.ucla.edu
* Edward Lu: edwardzlu98@gmail.com

We also thank Arthi Padmanabhan (artpad@cs.ucla.edu) for her previous work in NDND.

## How NDND works?

There are three participants in NDND protocol.

#### ND-Client:
When starts, It first registers the prefix `/<my_name>/nd-info`. This prefix is used for RV fetching Client NDND related info. Then Client register route to the ND-Server (or RV). The IP address and port number of RV is already known, either by the bootstrapping process or other methods. Afterwards, ND-Client does the following.

##### Arrival Interest
When starting neighbour discovery service, ND-Client first send out a Arrival Interest to notify RV in the network its arrival and expect no response. 
```
Name: /ndn/nd/arrival/<name_length>/<Name>/<IP>/<Port>/<timestamp>
```
The `<name_length>` here refers the length or size of ND-Client's name. For example, Name `/cs/client01` has `<name_length>` 2 and Name `/client01` has 1. `<IP>` and `<Port>` refers to the interface ND-Client want to commnunicate. Currently the prefix of this Interest is `/ndn/nd`. It's not settled, but still should be a namespace exclusively for NDND protocol usage.


##### RV Information Subscription
After Arrival Interest, ND-Client periodically send Interests to fetch lastest RV records. 
```
Name: /ndn/nd/<timestamp>
```
Consideration: Each Client's RV Subscription Interest should show no difference. Timestamp is the only component which uniquely identifies them.

RV records will be pushed back in the RV's response Data. One single RV record entry has the following structure.
```
{ Protocol || IP Address || Port || Name }
```
Each entry indicate one available endpoint at this time. One or multiple RV record entry will be given back, depending on the available endpoints. Because RV Information Subscription does not differ different clients, Entry of "myself" is also returned.

##### Neighbors Route Registeration
Parsing the records from the RV Information Subscription and register route for each neighbor.

##### Client Information Publishing
When ND-Client start, it registers the `/<my_name>/nd-info`. NDND related information on client side will publish here, replying the periodic Interests, which in high-level forms a Subscription. By default, ND-Client's IP address is put into the Data content. One can put other useful information in it.  

#### ND-Server (RV):
When starting neighbour discovery service, ND-Server registers the prefix `/ndn/nd`. The naming of this prefix is not settled, but should exclusively identify the NDND protocol. Then the ND-Server does the following.

##### Listening to Arrival Interest
Any new incoming Interest with `/ndn/nd/arrival` (no same nonce or timestamp found) will be treated as new ND-Client coming online. It will create a new record entry with parsed IP address, Port, and Name. Then register route to the new coming client.

##### Client Information Subscription
After ND-Client route registeration, ND-Server periodically send Interests to each ND-Client, which in high-level forms a Subscription. Interest is named by
```
Name: /<ND-Client Name>/nd-info/<timestamp>
```
In the default replied Data (if any), ND-Client's IP Address is expected. It's used by updating the record entries. Other information can also be put into Client Information.
TODO: Further discussion needed.

##### RV Information Publishing
For each RV Information Subscription Interest, ND-Server replies back all registered ND-Client entries.
```
Name:         /ndn/nd/<timestamp>
Content:      { Protocol || IP Address || Port || Name }
              { Protocol || IP Address || Port || Name }
              { Protocol || IP Address || Port || Name }
                                ...
Signature
```


#### Local NFD:
ND-Client manages the local NFD to create new face(s) and new route(s) to the neighbors. It uses the NFD Management Protocol (which can be found here https://redmine.named-data.net/projects/nfd/wiki/Management) in order to do the following things: 

##### 1) Create a face for all URI's it receives from the ND-Server by sending a FIB Management control command (a signed interest)

##### 2) Create a route for all URI and prefix pairs it receives from the ND-Server by sending a RIB Management control command (a signed interest)

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
./nd-client
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
