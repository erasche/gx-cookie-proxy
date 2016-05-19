gx-cookie-proxy
===============

gx-cookie-proxy is a WebSocket-aware SSL-capable HTTP reverse proxy/load
balancer based on [drunken-hipster](https://github.com/joinmytalk/drunken-hipster)

Building
--------

First, make sure you have the Go build environment correctly installed. See
http://golang.org/ for more information.

Then run "make". This will in turn call the go utility to build the load
balancer, resulting in a binary named hipsterd.


Configuration
-------------

A simple configuration example:

    [frontend frontend1]
    bind = 0.0.0.0:9000
    backends = backend1
    add-x-forwarded-for = true

    [backend backend1]
    connect = icanhazip.com
    galaxy_dburl = postgresql://galaxy:galaxy@localhost:32777/galaxy?client_encoding=utf8&sslmode=disable
    galaxy_secret = USING THE DEFAULT IS NOT SECURE!

This is probably the simplest example possible. It defines a frontend that
binds to `0.0.0.0:9000`, and forwards all its incoming requests to only one
backend. This backend will send these forwarded requests to `icanhazip.com`
with the appropriate `REMOTE_USER` setting if the user is logged in..

License
-------

See the file LICENSE for license information.

Author
------

Drunken Hipster - Andreas Krennmair <ak@synflood.at>
Galaxy Portions - Eric Rasche <esr@tamu.edu>
