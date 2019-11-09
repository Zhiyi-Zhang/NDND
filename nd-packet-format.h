// AUTHOR: Xinyu Ma
// License: LGPL v3.0
#ifndef _ND_PACKET_FORMAT_H
#define _ND_PACKET_FORMAT_H
#include <cstdint>

namespace ndn{
namespace ndnd{

#pragma pack(1)
typedef struct PARAMETER{
  uint8_t V4;
  uint8_t IpAddr[16];
  uint16_t Port;
  uint8_t SubnetMask[16];
  uint32_t TTL;
  uint64_t TimeStamp;
  uint8_t NamePrefix[0];
} *PPARAMETER;

typedef struct RESULT{
  uint8_t V4;
  uint8_t IpAddr[16];
  uint16_t Port;
  uint8_t NamePrefix[0];
} *PRESULT;
#pragma pack()

}; // ndnd
}; // ndn
#endif // _ND_PACKET_FORMAT_H