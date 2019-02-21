#include <ndn-cxx/face.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <chrono>
#include <ndn-cxx/util/sha256.hpp>
#include "nd-packet-format.h"
#include "nfd-command-tlv.h"
using namespace ndn;
using namespace ndn::ndnd;
using namespace std;


class NDNDClient{
public:
  
  void send_rib_register_interest(const Name& route_name, int face_id) {
    Interest interest(Name("/localhost/nfd/rib/register"));
    interest.setInterestLifetime(5_s);
    interest.setMustBeFresh(true);
    Block control_params = make_rib_register_interest_parameter(route_name, face_id);
    const_cast<Name&>(interest.getName()).append(control_params);
    interest.setParameters(m_buffer, m_len);
    interest.setNonce(4);
    interest.setCanBePrefix(false);

    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    const_cast<Name&>(interest.getName()).appendNumber(now);
    const_cast<Name&>(interest.getName()).appendNumber(now);
    
    m_keyChain.sign(interest);
    
    std::cerr << "Name of interest sent:" << std::endl;
    std::cerr << interest.getName().toUri() << std::endl;
    
    m_face.expressInterest(
      interest, 
      bind(&NDNDClient::onNFDCommandData, this,  _1, _2),
      bind(&NDNDClient::onNack, this,  _1, _2),
      bind(&NDNDClient::onTimeout, this,  _1));  
  }

  
  void run(){
    Interest interest(Name("/ndn/nd"));
    interest.setInterestLifetime(30_s);
    interest.setMustBeFresh(true);
    make_NDND_interest_parameter();
    interest.setParameters(m_buffer, m_len);
    interest.setNonce(4);
    interest.setCanBePrefix(false);

    name::Component parameterDigest = name::Component::fromParametersSha256Digest(
      util::Sha256::computeDigest(interest.getParameters().wire(), interest.getParameters().size()));

    const_cast<Name&>(interest.getName()).append(parameterDigest);

    m_face.expressInterest(
      interest, 
      bind(&NDNDClient::onData, this,  _1, _2),
      bind(&NDNDClient::onNack, this,  _1, _2),
      bind(&NDNDClient::onTimeout, this,  _1));

    m_face.processEvents();
  }

// private:
  void onData(const Interest& interest, const Data& data){
    std::cout << data << std::endl;

    size_t dataSize = data.getContent().value_size();
    auto pResult = reinterpret_cast<const RESULT*>(data.getContent().value());
    int iNo = 1;
    Name name;

    while((uint8_t*)pResult < data.getContent().value() + dataSize){
      m_len = sizeof(RESULT);
      printf("-----%2d-----\n", iNo);
      printf("IP: %s\n", inet_ntoa(*(in_addr*)(pResult->IpAddr)));
      printf("Port: %hu\n", ntohs(pResult->Port));
      printf("Subnet Mask: %s\n", inet_ntoa(*(in_addr*)(pResult->SubnetMask)));

      auto result = Block::fromBuffer(pResult->NamePrefix, data.getContent().value() + dataSize - pResult->NamePrefix);
      name.wireDecode(std::get<1>(result));
      printf("Name Prefix: %s\n", name.toUri().c_str());
      m_len += std::get<1>(result).size();

      pResult = reinterpret_cast<const RESULT*>(((uint8_t*)pResult) + m_len);
      iNo ++;
    }
  }

  void onNack(const Interest& interest, const lp::Nack& nack){
    std::cout << "received Nack with reason " << nack.getReason()
              << " for interest " << interest << std::endl;
  }

  void onTimeout(const Interest& interest){
    std::cout << "Timeout " << interest << std::endl;
  }


  Block make_rib_register_interest_parameter(const Name& route_name, int face_id) {
    
    std::cerr << "1" << std::endl;
    auto block = makeEmptyBlock(CONTROL_PARAMETERS);
    
    Block route_name_block = route_name.wireEncode();    
    
    Block face_id_block =
      makeNonNegativeIntegerBlock(FACE_ID, face_id);

    Block origin_block =
      makeNonNegativeIntegerBlock(ORIGIN, 0xFF);

    Block cost_block =
      makeNonNegativeIntegerBlock(COST, 0);

    Block flags_block =
      makeNonNegativeIntegerBlock(FLAGS, 0x01);
    
    std::cerr << "2" << std::endl;
    
    block.push_back(route_name_block);
    block.push_back(face_id_block);
    block.push_back(origin_block);
    block.push_back(cost_block);
    block.push_back(flags_block);
    
    std::cerr << "Route name block:" << std::endl;
    std::cerr << route_name_block << std::endl;
    std::cerr << "Face id block:" << std::endl;
    std::cerr << face_id_block << std::endl;
    
    std::cerr << "Control parameters block:" << std::endl;
    std::cerr << block << std::endl;
    
    block.encode();  
    // memcpy(m_buffer, block.begin().base(), block.size());
    // m_len = block.size();

    return block;    
  }
  
  void make_NDND_interest_parameter(){
    auto pParam = reinterpret_cast<PPARAMETER>(m_buffer);
    m_len = sizeof(PARAMETER);

    pParam->V4 = 1;
    memcpy(pParam->IpAddr, &m_IP, sizeof(in_addr_t));
    pParam->Port = m_port;
    memcpy(pParam->SubnetMask, &m_submask, sizeof(in_addr_t));
    pParam->TTL = 30 * 1000; //ms
    pParam->TimeStamp = chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now().time_since_epoch()).count();

    Block block = m_namePrefix.wireEncode();
    memcpy(pParam->NamePrefix, block.begin().base(), block.end() - block.begin());
    m_len += block.end() - block.begin();
  }

  void onNFDCommandData(const Interest& interest, const Data& data){
    std::cout << "onNFDCommandData got called." << std::endl;

    data.getContent().parse();
    data.getContent().get(CONTROL_RESPONSE).parse();
    std::cerr << data.getContent() << std::endl; 
  }


  void onAddFaceDataReply(const Interest& interest, const Data& data) {
    Block response_block = data.getContent().blockFromValue();
    response_block.parse();

    Block status_code_block = response_block.get(STATUS_CODE);
    Block status_text_block = response_block.get(STATUS_TEXT);
    short response_code = *(unsigned short *)status_code_block.value() & 0xff;
    char response_text[1000] = {0};
    memcpy(response_text, status_text_block.value(), status_text_block.value_size());

    std::cout << "\nAdding Face: " << response_code << " " << response_text << std::endl;
  }

  void addFace(string uri) {
    Name n("/localhost/nfd/faces/create");
    auto control_block = makeEmptyBlock(CONTROL_PARAMETERS);
    control_block.push_back(makeStringBlock(URI, uri));
    control_block.encode();
    n.append(control_block);
    Interest interest(n);
    m_face.expressInterest(
      interest, 
      bind(&NDNDClient::onAddFaceDataReply, this, _1, _2),
      bind(&NDNDClient::onNack, this, _1, _2),
      bind(&NDNDClient::onTimeout, this, _1));
  }

public:
  Face m_face;
  KeyChain m_keyChain;
  Name m_namePrefix;
  in_addr m_IP;
  in_addr m_submask;
  uint16_t m_port;
  uint8_t m_buffer[4096];
  size_t m_len;
};
NDNDClient *g_pClient;

int main(int argc, char *argv[]){
  g_pClient = new NDNDClient();

  inet_aton(argv[1], &g_pClient->m_IP);
  sscanf(argv[2], "%hu", &g_pClient->m_port);
  g_pClient->m_port = htons(g_pClient->m_port);
  inet_aton("255.255.255.0", &g_pClient->m_submask);
  g_pClient->m_namePrefix = Name("/test/01/02");

  try {
    // g_pClient->run();
    g_pClient->addFace(string("udp4://127.0.1.1:6363"));
    g_pClient->m_face.processEvents();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }

  delete g_pClient;
  return 0;
}
