#include <ndn-cxx/face.hpp>
#include <iostream>
using namespace ndn;

class NDNDClient{
public:
  void getLocalAddress(){
    ;
  }

  void run(){
    Interest interest(Name("/ndn/nd"));
    interest.setInterestLifetime(30_s);
    interest.setMustBeFresh(true);

    m_face.processEvents();
  }

public:
  Face m_face;
};
NDNDClient *g_pClient;

int main(int argc, char *argv[]){
  return -1;
}
