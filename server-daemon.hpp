// AUTHOR: Zhiyi Zhang
// EMAIL: zhiyi@cs.ucla.edu
// License: LGPL v3.0

#include <ndn-cxx/name.hpp>
#include <ndn-cxx/face.hpp>

namespace ndn {
namespace ndnd {

class DBEntry
{
public:
  bool v4;
  uint8_t ip[16];
  uint8_t mask[16];
  uint16_t port;
  uint32_t ttl;
  uint64_t tp;
  Name prefix;
  int faceId;
};

class NDServer
{
public:
  void
  registerPrefix(const Name& prefix);

  void
  run();

private:
  void
  onInterest(const Interest& request);

  void
  addRoute(const std::string& url, DBEntry& entry);

  void
  onData(const Data& data, DBEntry& entry);

private:
  Name m_prefix;
  Face m_face;
  KeyChain m_keyChain;
  std::list<DBEntry> m_db;
};

} // namespace ndnd
} // namespace ndn
