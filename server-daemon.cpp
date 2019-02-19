// AUTHOR: Zhiyi Zhang
// EMAIL: zhiyi@cs.ucla.edu
// License: LGPL v3.0

#include "server-daemon.hpp"

namespace ndn {
namespace ndnd {

static void
parseInterest(const Interest& interest)
{
}

static void
parseInterest(const std::list<DBEntry>& db, const uint8_t (&ipMatch)[], Buffer& result)
{
  result.clear();
  int counter = 0;
  for (const auto& item : db) {
    uint8_t itemIpPrefix[128] = {0};
    for (int i = 0; i < 128; i++) {
      itemIpPrefix[i] = item.ip[i] & item.mask[i];
    }
    if (memcmp(ipMatch, itemIpPrefix, 128) == 0) {
      // TODO: Freshness Check: TP + TTL compared with Current TP
      std::copy(item.ip, item.ip + 128, result.end());
      std::copy(item.mask, item.mask + 128, result.end());
      auto block = item.prefix.wireEncode();
      std::copy(block.wire(), block.wire() + 128, result.end());
      counter++;
    }
    if (counter > 10)
      break;
  }
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
  auto data = make_shared<Data>(request.getName());
  uint8_t ipMatch[128] = {0};
  for (int i = 0; i < 128; i++) {
    ipMatch[i] = entry.ip[i] & entry.mask[i];
  }
  Buffer contentBuf;
  parseInterest(m_db, ipMatch, contentBuf);
  data->setContent(contentBuf.get<uint8_t>(), contentBuf.size());

  m_keyChain.sign(*data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));
  // security::SigningInfo signInfo(security::SigningInfo::SIGNER_TYPE_ID, m_options.identity);
  // m_keyChain.sign(*m_data, signInfo);
  data->setFreshnessPeriod(time::milliseconds(4000));
  m_face.put(*data);
}

}
}
