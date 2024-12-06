# pymiproxy - Python Micro Interceptor Proxy

This is a Python 3 port of the original [PyMiProxy project](https://github.com/allfro/pymiproxy) by Nadeem Douba.
A small and sweet man-in-the-middle proxy capable of doing HTTP and HTTP over SSL.

## Introduction

pymiproxy is a small, lightweight, man-in-the-middle proxy capable of performing HTTP and HTTPS (or SSL) inspection. The
proxy provides a built-in certificate authority that is capable of generating certificates for SSL-based destinations.
Pymiproxy is also extensible and provides two methods for extending the proxy: method overloading, and a pluggable
interface. It is ideal for situations where you're in dire need of a cool proxy to tamper with out- and/or in-bound HTTP
data.

## Installation Requirements

The following modules are required:

- cryptography>=41.0.0

## Installation

Just run the following command at the command prompt:

```bash
$ python setup.py install
```

## Usage

The module offers a few examples in the code. In brief, pymiproxy can be run right-away by issuing the following command
at the command-prompt:

```bash
$ python -m miproxy.proxy
```

This will invoke pymiproxy with the `DebugInterceptor` plugin which simply outputs the first 100 bytes of each request
and response. The proxy runs on port 8080 and listens on all addresses.

To use the proxy:
1. Start the proxy server using the command above
2. Configure your browser to use localhost:8080 as the proxy
3. Browse websites and watch the intercepted traffic in your terminal
4. Use Ctrl+C to stop the proxy when done

## Extending or Implementing pymiproxy

There are two ways of extending the proxy:

- Develop and register an Interceptor plugin; or
- Overload the `mitm_request`, and `mitm_response` methods in the `ProxyHandler` class.

The decision on which method you choose to use is entirely dependent on whether or not you wish to push the data being
intercepted through a set of interceptors or not.

### Interceptor Plugins

There are currently two types of interceptor plugins:

- `RequestInterceptorPlugins`: executed prior to sending the request to the remote server; and
- `ResponseInterceptorPlugins`: executed prior to sending the response back to the client.

The following flow is taken by pymiproxy in this mode:

1. Client request received
2. Client request parsed
3. Client request processed/transformed by Request Interceptor plugins
4. Updated request sent to remote server
5. Response received by remote server
6. Response processed/transformed by Response Interceptor plugins
7. Updated response sent to client

You can register as many plugins as you wish. However, keep in mind that plugins are executed in the order that they are
registered in. Take care in how you register your plugins if the result of one plugin is dependent on the result of
another.

## Major Changes from Original Version

1. Updated for Python 3 compatibility:
   - Modernized imports (http.server, urllib.parse, etc.)
   - Updated exception handling syntax
   - Fixed print statements

2. Security Improvements:
   - Replaced deprecated OpenSSL with modern cryptography library
   - Improved certificate generation and handling
   - Added proper SSL context configuration

3. Dependencies:
   - Removed pyOpenSSL dependency
   - Added cryptography as the main dependency

4. Other Changes:
   - Improved error handling
   - Better file handling with context managers
   - Updated regex patterns
