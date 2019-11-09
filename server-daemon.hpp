// AUTHOR: Zhiyi Zhang
// EMAIL: zhiyi@cs.ucla.edu
// License: LGPL v3.0

#include <ndn-cxx/name.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/scheduler.hpp>

namespace ndn {
namespace ndnd {

class DBEntry
{
public:
  bool v4;
  // An entry is not confirmed until route registeration succeed
  bool confirmed;
  uint8_t ip[16];
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
  // if subscribe interest, return 0; if arrival interest, return 1
  int
  parseInterest(const Interest& request, DBEntry& entry);

  void
  subscribeBack(const std::string& url);

  void
  onSubData(const Data& data);
  void
  onSubTimeout(const Interest& interest);

  void
  addRoute(const std::string& url, DBEntry& entry);

  DBEntry&
  findEntry(const Name& name);

  void
  removeRoute(DBEntry& entry);

  void
  onInterest(const Interest& request);
  void
  onData(const Data& data, DBEntry& entry);
  void 
  onNack(const Interest& interest, const lp::Nack& nack);

private:
  Name m_prefix;
  uint64_t m_ttl;
  Face m_face;
  KeyChain m_keyChain;
  Scheduler *m_scheduler;
  std::list<DBEntry> m_db;
};

} // namespace ndnd
} // namespace ndn
