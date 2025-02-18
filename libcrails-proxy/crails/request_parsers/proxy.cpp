#include "proxy.hpp"
#include <crails/logger.hpp>
#include <crails/context.hpp>
#include <crails/http_response.hpp>
#include <crails/params.hpp>
#include <crails/client.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace Crails;

ProxyRequestHandler::ProxyRequestHandler(const Rules& rules, const Mode default_mode) :
  default_mode(default_mode),
  rules(std::move(rules))
{
}

void ProxyRequestHandler::operator()(Context& context, function<void (RequestParser::Status)> callback) const
{
  const auto& request = context.connection->get_request();
  auto& response = context.response;
  string destination(request.target());
  auto it = find(rules.cbegin(), rules.cend(), destination);

  if (it != rules.end())
  {
    const Rule& rule = *it;

    context.params["uri"] = request.target();
    context.vars["proxy-rule"] = &rule;
    if (request.method() != HttpVerb::get && request.method() != HttpVerb::head)
    {
      wait_for_body(context, [this, callback, &context, &rule]()
      {
        execute_rule(rule, context, std::bind(callback, RequestParser::Abort));
      });
    }
    else
      execute_rule(rule, context, std::bind(callback, RequestParser::Abort));
  }
  else
    callback(RequestParser::Continue);
}

void ProxyRequestHandler::body_received(Context& context, const std::string& body) const
{
  const Rule& rule = *(cast<const Rule*>(context.vars, "proxy-rule"));

  context.vars["body"] = &body;
}

void ProxyRequestHandler::execute_rule(const Rule& rule, Context& context, std::function<void()> callback) const
{
  const auto& request = context.connection->get_request();
  string destination(request.target());
  Mode mode = rule.mode == DefaultMode ? default_mode : rule.mode;

  if (mode == Redirect302)
  {
    auto proxy_request = rule(request, string());
    context.response.set_header(HttpHeader::location, get_proxyfied_url(proxy_request));
    context.response.set_response(HttpStatus::temporary_redirect, string_view(""));
    context.response.send();
    callback();
  }
  else if (request.method() != HttpVerb::get && request.method() != HttpVerb::head)
  {
    wait_for_body(context, [this, callback, &context, &rule]()
    {
      proxy(rule, context, callback);
    });
  }
  else
    proxy(rule, context, callback);
}

string ProxyRequestHandler::get_proxyfied_url(const ProxyRequest& request)
{
  stringstream result;

  result << (request.ssl ? "https": "http") << "://";
  result << request.host << ':' << request.port << '/';
  result << request.target();
  return result.str();
}

static void on_proxy_failure(const char* message, BuildingResponse& response, std::function<void()> callback)
{
  logger << "Crails::Proxy: failed to proxy request towards: " << message << Logger::endl;
  response.set_status_code(HttpStatus::internal_server_error);
  response.send();
  callback();
}

void ProxyRequestHandler::proxy(const Rule& rule, Context& context, std::function<void()> callback) const
{
  shared_ptr<ClientInterface> http_client;
  SharedVars::const_iterator body_var = context.vars.find("body");
  const string* body = body_var != context.vars.end() ? cast<const string*>(context.vars, "body") : nullptr;
  ProxyRequest proxy_request = rule(context.connection->get_request(), body ? *body : std::string());

  if (proxy_request.ssl)
    http_client = make_shared<Ssl::Client>(proxy_request.host, proxy_request.port);
  else
    http_client = make_shared<Client>(proxy_request.host, proxy_request.port);
  try
  {
    logger << "Crails:Proxy proxifying towards " << proxy_request.host << ':' << proxy_request.port << proxy_request.target() << Logger::endl;
    http_client->connect();
    http_client->async_query(proxy_request, [&context, callback, http_client](const ClientResponse& remote_response, boost::beast::error_code ec)
    {
      context.protect([&context, callback, &remote_response, ec]()
      {
        if (!ec)
        {
          context.response.get_raw_response() = remote_response;
          context.response.send();
          callback();
        }
        else
          on_proxy_failure(ec.message().c_str(), context.response, callback);
      });
      try { http_client->disconnect(); } catch (...) {}
    });
  }
  catch (const std::exception& exception)
  {
    on_proxy_failure(exception.what(), context.response, callback);
  }
}
