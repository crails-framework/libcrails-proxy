#include <crails/url.hpp>
#include <crails/http.hpp>
#include "proxy.hpp"

using namespace std;
using namespace Crails;

ProxyRequestHandler::ProxyRequestHandler::Rule::Rule(const char* regex, const char* url_string, ProxyRequestHandler::Mode mode) :
  matcher(regex, std::regex_constants::optimize),
  mode(mode)
{
  Url url = Url::from_string(url_string);
  ProxyRequest base;

  base.ssl  = url.ssl;
  base.host = url.host;
  base.port = url.port;
  base.method(HttpVerb::get);
  base.target(url.target);
  base.set(HttpHeader::host, url.host);
  solver = std::bind(&Rule::defaultSolver, base, placeholders::_1, placeholders::_2, placeholders::_3);
}

ProxyRequestHandler::Rule::Rule(const char* regex, ProxyRequestHandler::RuleSolver solver) : matcher(regex), mode(ProxyRequestHandler::Proxy), solver(solver)
{
}

ProxyRequestHandler::ProxyRequest ProxyRequestHandler::Rule::operator()(const HttpRequest& source, const string& body) const
{
  std::smatch matches;
  std::string uri(source.target());

  std::regex_search(uri, matches, matcher);
  return solver(source, body, matches);
}

ProxyRequestHandler::ProxyRequest ProxyRequestHandler::Rule::defaultSolver(ProxyRequest result, const HttpRequest& source, const std::string& body, const std::smatch& matches)
{
  string base_target(result.target());
  string suffix(matches.suffix());

  for (auto it = source.cbegin() ; it != source.cend() ; ++it)
  {
    if (it->name() != HttpHeader::host)
      result.insert(it->name_string(), it->value());
  }
  if (suffix.length() > 0)
  {
    if (suffix[0] != '/' && suffix[0] != '?')
      suffix = '/' + suffix;
    result.target(base_target + suffix);
  }
  else
    result.target("/");
  result.body() = body;
  return result;
}
