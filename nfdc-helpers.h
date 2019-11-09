// AUTHOR: Zhiyi Zhang
// EMAIL: zhiyi@cs.ucla.edu
// License: LGPL v3.0

#include "nfd-command-tlv.h"
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/encoding/tlv.hpp>
#include <ndn-cxx/security/command-interest-signer.hpp>
#include <iostream>

namespace ndn {
namespace ndnd {

static Block
make_rib_unregeister_interest_parameter(const Name& route_name, int face_id)
{
  auto block = makeEmptyBlock(CONTROL_PARAMETERS);
  Block route_name_block = route_name.wireEncode();
  Block face_id_block = makeNonNegativeIntegerBlock(FACE_ID, face_id);
  Block origin_block = makeNonNegativeIntegerBlock(ORIGIN, 0xFF);

  block.push_back(route_name_block);
  block.push_back(face_id_block);
  block.push_back(origin_block);

  std::cerr << "Route name block:" << std::endl;
  std::cerr << route_name_block << std::endl;
  std::cerr << "Face id block:" << std::endl;
  std::cerr << face_id_block << std::endl;
  std::cerr << "Control parameters block:" << std::endl;
  std::cerr << block << std::endl;
  block.encode();
  return block;
}

static Block
make_rib_interest_parameter(const Name& route_name, int face_id)
{
  auto block = makeEmptyBlock(CONTROL_PARAMETERS);
  Block route_name_block = route_name.wireEncode();
  Block face_id_block = makeNonNegativeIntegerBlock(FACE_ID, face_id);
  Block origin_block = makeNonNegativeIntegerBlock(ORIGIN, 0xFF);
  Block cost_block = makeNonNegativeIntegerBlock(COST, 0);
  Block flags_block = makeNonNegativeIntegerBlock(FLAGS, 0x01);

  block.push_back(route_name_block);
  block.push_back(face_id_block);
  block.push_back(origin_block);
  block.push_back(cost_block);
  block.push_back(flags_block);

  std::cerr << "Route name block:" << std::endl;
  std::cerr << route_name_block << std::endl;
  std::cerr << "Face id block:" << std::endl;
  std::cerr << face_id_block << std::endl;
  std::cerr << "Control parameters block:" << std::endl;
  std::cerr << block << std::endl;
  block.encode();
  return block;
}

static Interest
prepareRibUnregisterInterest(const Name& route_name, int face_id, KeyChain& keychain,
                           int cost = 0)
{
  Name name("/localhost/nfd/rib/unregister");
  Block control_params = make_rib_unregeister_interest_parameter(route_name, face_id);
  name.append(control_params);

  security::CommandInterestSigner signer(keychain);
  Interest interest = signer.makeCommandInterest(name);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(false);
  return interest;
}

static Interest
prepareRibRegisterInterest(const Name& route_name, int face_id, KeyChain& keychain,
                           int cost = 0)
{
  Name name("/localhost/nfd/rib/register");
  Block control_params = make_rib_interest_parameter(route_name, face_id);
  name.append(control_params);

  security::CommandInterestSigner signer(keychain);
  Interest interest = signer.makeCommandInterest(name);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(false);
  return interest;
}

static Interest
prepareFaceCreationInterest(const std::string& uri, KeyChain& keychain)
{
  Name name("/localhost/nfd/faces/create");
  auto control_block = makeEmptyBlock(CONTROL_PARAMETERS);
  control_block.push_back(makeStringBlock(URI, uri));
  control_block.encode();
  name.append(control_block);

  security::CommandInterestSigner signer(keychain);
  Interest interest = signer.makeCommandInterest(name);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(false);
  return interest;
}

static Interest
prepareFaceDestroyInterest(int face_id, KeyChain& keychain)
{
  Name name("/localhost/nfd/faces/destroy");
  auto control_block = makeEmptyBlock(CONTROL_PARAMETERS);
  control_block.push_back(makeNonNegativeIntegerBlock(FACE_ID, face_id));
  control_block.encode();
  name.append(control_block);

  security::CommandInterestSigner signer(keychain);
  Interest interest = signer.makeCommandInterest(name);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(false);
  return interest;
}

static Interest
prepareStrategySetInterest(const std::string& prefix, const std::string& strategy,
                           KeyChain& keychain) {
  Name name("/localhost/nfd/strategy-choice/set");
  
  auto prefix_block = Name(prefix).wireEncode();
  auto strategy_block = makeEmptyBlock(STRATEGY);
  strategy_block.push_back(Name(strategy).wireEncode());

  auto control_block = makeEmptyBlock(CONTROL_PARAMETERS);
  control_block.push_back(prefix_block);
  control_block.push_back(strategy_block);
  control_block.encode();
  name.append(control_block);

  security::CommandInterestSigner signer(keychain);
  Interest interest = signer.makeCommandInterest(name);
  interest.setMustBeFresh(true);
  interest.setCanBePrefix(false);
  return interest;
}

} // namespace ndnd
} // namespace ndn