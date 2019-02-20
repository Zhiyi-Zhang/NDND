// AUTHOR: Zhiyi Zhang
// EMAIL: zhiyi@cs.ucla.edu
// License: LGPL v3.0

#include "server-daemon.hpp"
#include "nd-packet-format.h"
#include <iostream>

namespace ndn {
namespace ndnd {

static void
parseInterest(const Interest& interest, DBEntry& entry)
{
  auto paramBlock = interest.getParameters();

  struct PARAMETER param;
  memcpy(&param, paramBlock.value(), sizeof(struct PARAMETER));

  for (int i = 0; i < paramBlock.value_size(); i++) {
    printf("%02x", paramBlock.value()[i]);
  }
    // std::cout << std::hex << paramBlock.value()[i];

  Name prefix;
  Block nameBlock(paramBlock.value() + sizeof(struct PARAMETER),
                  paramBlock.value_size() - sizeof(struct PARAMETER));
  prefix.wireDecode(nameBlock);

  entry.v4 = (param.V4 == 1)? 1 : 0;
  memcpy(entry.ip, param.IpAddr, 16);
  memcpy(entry.mask, param.SubnetMask, 16);
  entry.port = param.Port;
  entry.ttl = param.TTL;
  entry.tp = param.TimeStamp;
  entry.prefix = prefix;

  std::cout << "finish parse" << std::endl
            << prefix.toUri() << std::endl;
}

static void
genReplyBuffer(const std::list<DBEntry>& db, const uint8_t (&ipMatch)[16], Buffer& resultBuf)
{
  resultBuf.clear();
  int counter = 0;
  for (const auto& item : db) {
    uint8_t itemIpPrefix[16] = {0};
    for (int i = 0; i < 16; i++) {
      itemIpPrefix[i] = item.ip[i] & item.mask[i];
      std::cout << itemIpPrefix[i] << std::endl;
    }
    if (memcmp(ipMatch, itemIpPrefix, 16) == 0) {
      // TODO: Freshness Check: TP + TTL compared with Current TP

      struct RESULT result;
      result.V4 = item.v4? 1 : 0;
      memcpy(result.IpAddr, item.ip, 16);
      result.Port = item.port;
      memcpy(result.SubnetMask, item.mask, 16);

      int max = resultBuf.size() + sizeof(struct RESULT);
      for (int i = resultBuf.size(); i < max; i++) {
        resultBuf.push_back(*((uint8_t*)&result + i));
      }


      auto block = item.prefix.wireEncode();
      max = resultBuf.size() + block.size();
      for (int i = resultBuf.size(); i < max; i++) {
        resultBuf.push_back(*(block.wire() + i));
      }
      counter++;
    }
    if (counter > 10)
      break;
  }
  std::cout << "matched entries number" << counter << std::endl;
}

void
NDServer::run()
{
  m_face.processEvents();
}

void
NDServer::registerPrefix(const Name& prefix)
{
  m_prefix = prefix;
  auto prefixId = m_face.setInterestFilter(InterestFilter(m_prefix),
                                           bind(&NDServer::onInterest, this, _2), nullptr);
}

void
NDServer::onInterest(const Interest& request)
{
  DBEntry entry;
  parseInterest(request, entry);
  m_db.push_back(entry);
  uint8_t ipMatch[16] = {0};
  for (int i = 0; i < 16; i++) {
    ipMatch[i] = entry.ip[i] & entry.mask[i];
  }

  std::cout << "are you okay"<< std::endl;

  auto data = make_shared<Data>(request.getName());
  Buffer contentBuf;
  genReplyBuffer(m_db, ipMatch, contentBuf);
  std::cout << "hello"<< std::endl;
  data->setContent(contentBuf.get<uint8_t>(), contentBuf.size());

  m_keyChain.sign(*data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));
  // security::SigningInfo signInfo(security::SigningInfo::SIGNER_TYPE_ID, m_options.identity);
  // m_keyChain.sign(*m_data, signInfo);
  data->setFreshnessPeriod(time::milliseconds(4000));
  m_face.put(*data);
}

}
}
