#ifndef  PROXY_REQUEST_HANDLER_HPP
# define PROXY_REQUEST_HANDLER_HPP

# include <crails/request_parser.hpp>
# include <regex>

namespace Crails
{
  class ProxyRequestHandler : public BodyParser
  {
  public:
    enum Mode
    {
      Redirect302,
      Proxy
    };

    typedef boost::beast::http::request<boost::beast::http::string_body>  ClientRequest;
    typedef boost::beast::http::response<boost::beast::http::string_body> ClientResponse;

    struct ProxyRequest : public ClientRequest
    {
      ProxyRequest() {}
      ProxyRequest(boost::beast::http::verb method, const std::string& host, unsigned short port, const std::string& target, unsigned int http_version = 11) : ClientRequest{method, target, http_version}, host(host), port(port) {}
      ProxyRequest(boost::beast::http::verb method, const std::string& host, std::string& target) : ClientRequest{method, target, 11}, host(host), port(80) {}

      ProxyRequest& with_ssl() { ssl = true; return *this; }

      bool ssl = false;
      std::string host;
      unsigned short port;
    };

    typedef std::function<ProxyRequest (const HttpRequest&, const std::string&, const std::smatch&)> RuleSolver;

    struct Rule
    {
      Rule(const char* regex, const char* target, Mode = ProxyRequestHandler::default_mode);
      Rule(const char* regex, RuleSolver solver);

      bool operator==(const std::string& uri) const { return solver && std::regex_search(uri.c_str(), matcher); }
      ProxyRequest operator()(const HttpRequest& source, const std::string& body) const;
      static ProxyRequest defaultSolver(ProxyRequest base, const HttpRequest& source, const std::string& body, const std::smatch&);

      std::regex matcher;
      Mode       mode;
      RuleSolver solver;
    };

    typedef std::vector<Rule> Rules;
    friend struct Rule;

    ProxyRequestHandler();

    void operator()(Context&, std::function<void(RequestParser::Status)>) const override;
  private:
    void body_received(Context&, const std::string&) const override;
    void execute_rule(const Rule&, Context&, std::function<void()> callback) const;
    void proxy(const Rule&, Context&, std::function<void()> callback) const;
    static std::string get_proxyfied_url(const ProxyRequest&);

    static const Mode  default_mode;
    static const Rules rules;
  };
}

#endif
