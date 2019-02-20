// AUTHOR: Zhaoning Kong
// EMAIL: jonnykong@cs.ucla.edu
// License: LGPL v3.0

#include "nd-client.cpp"

#include <iostream>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <ndn-cxx/face.hpp>

using namespace std;

namespace po = boost::program_options;

static void
usage(std::ostream& os, const po::options_description& options)
{
  os << "Usage: Named Data Neighbor Discovery (NDND) Client App\n"
        "\n"
     << options;
}

class Options
{
public:
  Options()
    : prefix("/ndn/nd")
  {
  }

public:
  ndn::Name prefix;
};

namespace ndn {
namespace ndnd {

class Program
{
public:
  explicit Program(const Options& options)
    : m_options(options)
  {
    // Init client
    m_client = new NDNDClient();
    inet_aton("localhost", &m_client->m_IP);           // TODO: Bootstrap
    inet_aton("255.255.255.0", &m_client->m_submask);  // TODO: Bootstrap
    m_client->m_port = htons(6363);
    m_client->m_namePrefix = Name("/test/01/02");
    
    m_client->run();
  }

  ~Program() {
    delete m_client;
  }


private:
  const Options m_options;
  NDNDClient *m_client;
};


} // namespace ndnd
} // namespace ndn

int
main(int argc, char** argv)
{
  Options opt;
  ndn::ndnd::Program program(opt);
}