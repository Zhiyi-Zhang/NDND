// AUTHOR: Zhiyi Zhang
// EMAIL: zhiyi@cs.ucla.edu
// License: LGPL v3.0

#include "server-daemon.hpp"
#include "nfdc-helpers.h"
#include "nd-packet-format.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <chrono>
#include <iostream>

namespace ndn {
namespace ndnd {

static std::string
getFaceUri(const DBEntry& entry)
{
  std::string result = "udp4://";
  result += inet_ntoa(*(in_addr*)(entry.ip));
  result += ':';
  result += std::to_string(entry.port);
  return result;
}

static void
parseInterest(const Interest& interest, DBEntry& entry)
{
  auto paramBlock = interest.getApplicationParameters();

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
  entry.faceId = -1;

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
    // create the entry for the requester if there is no matching entry in db
    m_db.push_back(entry);
    addRoute(getFaceUri(entry), entry);
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

void
NDServer::addRoute(const std::string& url, DBEntry& entry)
{
  auto Interest = prepareFaceCreationInterest(url, m_keyChain);
  m_face.expressInterest(Interest,
                         std::bind(&NDServer::onData, this, _2, entry),
                         nullptr,
                         nullptr);
}

void
NDServer::onData(const Data& data, DBEntry& entry)
{
  Name ribRegisterPrefix("/localhost/nfd/rib/register");
  Name faceCreationPrefix("/localhost/nfd/faces/create");
  Name faceDestroyPrefix("/localhost/nfd/faces/destroy");
  if (ribRegisterPrefix.isPrefixOf(data.getName())) {
    Block response_block = data.getContent().blockFromValue();
    response_block.parse();
    int responseCode = readNonNegativeIntegerAs<int>(response_block.get(STATUS_CODE));
    std::string responseTxt = readString(response_block.get(STATUS_TEXT));

    // Get FaceId for future removal of the face
    if (responseCode == OK) {
      Block controlParam = response_block.get(CONTROL_PARAMETERS);
      controlParam.parse();

      Name route_name(controlParam.get(ndn::tlv::Name));
      int face_id = readNonNegativeIntegerAs<int>(controlParam.get(FACE_ID));
      int origin = readNonNegativeIntegerAs<int>(controlParam.get(ORIGIN));
      int route_cost = readNonNegativeIntegerAs<int>(controlParam.get(COST));
      int flags = readNonNegativeIntegerAs<int>(controlParam.get(FLAGS));

      std::cout << "\nRegistration of route succeeded:" << std::endl;
      std::cout << "Status text: " << responseTxt << std::endl;
      std::cout << "Route name: " << route_name.toUri() << std::endl;
      std::cout << "Face id: " << face_id << std::endl;
      std::cout << "Origin: " << origin << std::endl;
      std::cout << "Route cost: " << route_cost << std::endl;
      std::cout << "Flags: " << flags << std::endl;
    }
    else {
      std::cout << "\nRegistration of route failed." << std::endl;
      std::cout << "Status text: " << responseTxt << std::endl;
    }
  }
  else if (faceCreationPrefix.isPrefixOf(data.getName())) {
    Block response_block = data.getContent().blockFromValue();
    response_block.parse();
    int responseCode = readNonNegativeIntegerAs<int>(response_block.get(STATUS_CODE));
    std::string responseTxt = readString(response_block.get(STATUS_TEXT));

    // Get FaceId for future removal of the face
    if (responseCode == OK) {
      Block status_parameter_block = response_block.get(CONTROL_PARAMETERS);
      status_parameter_block.parse();
      int face_id = readNonNegativeIntegerAs<int>(status_parameter_block.get(FACE_ID));
      std::cout << responseCode << " " << responseTxt
                << ": Added Face (FaceId: " << face_id
                << std::endl;

      entry.faceId = face_id;
      auto Interest = prepareRibRegisterInterest(entry.prefix, face_id, m_keyChain);
      m_face.expressInterest(Interest,
                             std::bind(&NDServer::onData, this, _2, entry),
                             nullptr, nullptr);
    }
    else {
      std::cout << "\nCreation of face failed." << std::endl;
      std::cout << "Status text: " << responseTxt << std::endl;
    }
  }
  else if (faceDestroyPrefix.isPrefixOf(data.getName())) {

  }
}

} // namespace ndnd
} // namespace ndn
