// AUTHOR: Zhiyi Zhang
// EMAIL: zhiyi@cs.ucla.edu
// License: LGPL v3.0

#include "server-daemon.hpp"
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <iostream>

namespace po = boost::program_options;

static void
usage(std::ostream& os, const po::options_description& options)
{
  os << "Usage: Named Data Neighbor Discovery (NDND) Server\n"
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
  explicit
  Program(const Options& options)
    : m_options(options)
    , server()
  {
  }

  void
  run()
  {
    server.registerPrefix(m_options.prefix);
    server.run();
  }

private:
  const Options m_options;
  NDServer server;
};

} // namespace ndnd
} // namespace ndn

int
main(int argc, char** argv)
{
  Options opt;

  po::options_description options("Required options");
  options.add_options()
    ("help,h", "print help message")
    ("prefix,P", po::value<ndn::Name>(&opt.prefix), "prefix to register");
  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, options), vm);
    po::notify(vm);
  }
  catch (boost::program_options::error&) {
    usage(std::cerr, options);
    return 2;
  }

  ndn::ndnd::Program program(opt);
  program.run();
  return 1;
}
