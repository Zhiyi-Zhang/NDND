// AUTHOR: Zhiyi Zhang
// EMAIL: zhiyi@cs.ucla.edu
// License: LGPL v3.0

#include <ndn-cxx/name.hpp>

namespace ndn {
namespace ndnd {

class Entry
{
public:
  bool v4;
  uint8_t[128] ip;
  uint16 port;
  uint32 ttl;
  uint64 tp;
  Name prefix;
};

class NDServer
{
public:
  void
  run();

private:
  void
  registerPrefix(const Name& prefix);

  void
  onInterest();

private:
  Name m_prefix;
  Face m_face;
  std::list<Entry> m_db;
};

} // namespace ndnd
} // namespace ndn
