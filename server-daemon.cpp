// AUTHOR: Zhiyi Zhang
// EMAIL: zhiyi@cs.ucla.edu
// License: LGPL v3.0

#include "server-daemon.hpp"
#include "nd-packet-format.h"
#include <chrono>
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
  uint8_t ipMatch[16] = {0};
  for (int i = 0; i < 16; i++) {
    ipMatch[i] = entry.ip[i] & entry.mask[i];
  }

  Buffer contentBuf;
  bool isUpdate = false;
  int counter = 0;
  for (auto it = m_db.begin(); it != m_db.end();) {
    const auto& item = *it;
    // if there is an existing entry for the same client, update it
    if (memcmp(entry.ip, item.ip, 16) == 0 && memcmp(entry.mask, item.mask, 16) == 0) {
      isUpdate = true;
      *it = entry;
      it++;
      continue;
    }

    using namespace std::chrono;
    milliseconds ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch());
    if (item.tp + item.ttl < ms.count()) {
      // if the entry is out-of-date, erase it
      m_db.erase(it);
    }
    else {
      // else, check the masked IP address, add the entry to the reply if it matches
      uint8_t itemIpPrefix[16] = {0};
      for (int i = 0; i < 16; i++) {
        itemIpPrefix[i] = item.ip[i] & item.mask[i];
        std::cout << itemIpPrefix[i] << std::endl;
      }
      if (memcmp(ipMatch, itemIpPrefix, 16) == 0) {
        struct RESULT result;
        result.V4 = item.v4? 1 : 0;
        memcpy(result.IpAddr, item.ip, 16);
        result.Port = item.port;
        memcpy(result.SubnetMask, item.mask, 16);

        for (int i = 0; i < sizeof(struct RESULT); i++) {
          contentBuf.push_back(*((uint8_t*)&result + i));
        }
        auto block = item.prefix.wireEncode();
        for (int i =0; i < block.size(); i++) {
          contentBuf.push_back(*(block.wire() + i));
        }
        counter++;
        it++;
      }
      if (counter > 10)
        break;
    }
  }
  if (!isUpdate) {
    m_db.push_back(entry);
  }

  auto data = make_shared<Data>(request.getName());
  if (contentBuf.size() > 0) {
    data->setContent(contentBuf.get<uint8_t>(), contentBuf.size());
  }
  else {
    return;
  }

  m_keyChain.sign(*data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));
  // security::SigningInfo signInfo(security::SigningInfo::SIGNER_TYPE_ID, m_options.identity);
  // m_keyChain.sign(*m_data, signInfo);
  data->setFreshnessPeriod(time::milliseconds(4000));
  m_face.put(*data);
}

} // namespace ndnd
} // namespace ndn
