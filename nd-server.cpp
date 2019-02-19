#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/transform.hpp>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>

namespace po = boost::program_options;

static void
usage(std::ostream& os, const po::options_description& options)
{
  os << "Usage: Tool for making data packet. Data can be signed using sha256 or by an identity\n"
        "ndnmkdata -identity /signing_identity -data /data/name\n"
        "ndnmkdata -sha256 -data /data/name\n"
        "\n"
     << options;
}

class Options
{
public:
  Options()
    : sha256(true)
  {
  }

public:
  bool sha256;
  ndn::Name identity;
  ndn::Name dataName;
  std::string content;
};

namespace ndn {
namespace mkdata {

class Program
{
public:
  explicit
  Program(const Options& options)
    : m_options(options)
    , m_keyChain()
  {
  }

  void
  run()
  {
    m_data = make_shared<Data>(m_options.dataName);
    if (m_options.sha256) {
      // sign with sha256
      m_keyChain.sign(*m_data, security::SigningInfo(security::SigningInfo::SIGNER_TYPE_SHA256));
    }
    else {
      // sign by identity
      security::SigningInfo signInfo(security::SigningInfo::SIGNER_TYPE_ID, m_options.identity);
      m_keyChain.sign(*m_data, signInfo);
    }
    m_data->setFreshnessPeriod(time::milliseconds(0));
    Block dataBlock = m_data->wireEncode();
    output(dataBlock);
  }

private:
  void
  output(const Block& dataBlock)
  {
    // print result to std output
    security::transform::bufferSource(dataBlock.wire(), dataBlock.size())
      >> security::transform::streamSink(std::cout);
  }

private:
  const Options m_options;
  security::KeyChain m_keyChain;
  shared_ptr<Data> m_data;
};

} // namespace mkdata
} // namespace ndn

int
main(int argc, char** argv)
{
  Options opt;

  po::options_description options("Required options");
  options.add_options()
    ("help,h", "print help message")
    ("identity,I", po::value<ndn::Name>(&opt.identity), "signing identity")
    ("sha256", "using sha256 for signature")
    ("data,D", po::value<ndn::Name>(&opt.dataName)->required(), "data name")
    ("input", po::value<std::string>(&opt.content), "input content")
    ;
  po::variables_map vm;
  try {
    po::store(po::parse_command_line(argc, argv, options), vm);
    po::notify(vm);
  }
  catch (boost::program_options::error&) {
    usage(std::cerr, options);
    return 2;
  }
  if (vm.count("help") > 0) {
    usage(std::cerr, options);
  }
  if (vm.count("sha256") > 0) {
    opt.sha256 = true;
  }
  if (vm.count("identity") > 0) {
    opt.sha256 = false;
  }

  ndn::mkdata::Program program(opt);
  program.run();

  return 1;
}
