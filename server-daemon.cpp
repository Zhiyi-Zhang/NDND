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

void
NDServer::run()
{
  face.processEvents();
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
  m_data = make_shared<Data>(m_options.dataName);
  m_keyChain.sign(*m_data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));

  // // sign by identity
  // security::SigningInfo signInfo(security::SigningInfo::SIGNER_TYPE_ID, m_options.identity);
  // m_keyChain.sign(*m_data, signInfo);

  m_data->setFreshnessPeriod(time::milliseconds(4000));
  Block dataBlock = m_data->wireEncode();
  output(dataBlock);
}

}
}
