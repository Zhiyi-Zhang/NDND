#include <ndn-cxx/face.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <chrono>
#include <ndn-cxx/util/sha256.hpp>
#include "nd-packet-format.h"
using namespace ndn;
using namespace ndn::ndnd;
using namespace std;

class NDNDClient{
public:
  void run(){
    Interest interest(Name("/ndn/nd"));
    interest.setInterestLifetime(30_s);
    interest.setMustBeFresh(true);
    makeParameter();
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

  void makeParameter(){
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

public:
  Face m_face;
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
    g_pClient->run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }

  delete g_pClient;
  return 0;
}
