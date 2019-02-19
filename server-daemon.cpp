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
parseInterest(const std::list<Entry>& db, const uint8_t[128]& entry, Buffer& result)
{
  result.clear();
  int counter = 0;
  for (const auto& item : db) {
    if (ipMatch ^ (item.ip & item.mask) == 0) {
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
  ipMatch = entry.ip & entry.mask;

  Buffer content;
  parseInterest(m_db, ipMatch, content);
  data->setContent(content);

  m_keyChain.sign(*m_data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));
  // security::SigningInfo signInfo(security::SigningInfo::SIGNER_TYPE_ID, m_options.identity);
  // m_keyChain.sign(*m_data, signInfo);
  data->setFreshnessPeriod(time::milliseconds(4000));
  m_face.put(*data);
}

}
}
