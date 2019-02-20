// AUTHOR: Zhaoning Kong
// EMAIL: jonnykong@cs.ucla.edu
// License: LGPL v3.0

#include "nd-client.cpp"

#include <iostream>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/asio.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/scheduler.hpp>

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

    m_scheduler = new Scheduler(m_io_service);

    loop();
    m_io_service.run();
  }

  void loop() {
    m_scheduler->scheduleEvent(time::seconds(1), [this] {
      m_client->run();
      loop();
    });
  }

  ~Program() {
    delete m_client;
    delete m_scheduler;
  }


private:
  const Options m_options;
  NDNDClient *m_client;
  Scheduler *m_scheduler;
  boost::asio::io_service m_io_service;
};


} // namespace ndnd
} // namespace ndn

int
main(int argc, char** argv)
{
  Options opt;
  ndn::ndnd::Program program(opt);
}