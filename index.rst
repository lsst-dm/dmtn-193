:tocdepth: 1

.. sectnum::

Abstract
========

The Rubin Science Platform consists of a set of services accessed via HTTP with a shared authentication and security layer.
The underlying applications will come from various sources and be written by teams with varying levels of knowledge of web security defenses.
It also includes the Notebook Aspect, which is arbitrary code execution as a service and thus poses unique security challenges.
This document proposes a threat model for thinking about web security for the Rubin Science Platform as a whole and discusses design approaches and mitigations to maximize the effective security of the overall platform without assuming detailed security design of each component.

Definitions and scope
=====================

Web security is the branch of application security focused on applications accessible via HTTP.
The term can encompass any aspect of the security of an application accessible via the web, which is too broad to be useful.
This document will focus specifically on aspects of security unique to web applications accessible via a web browser or an HTTP-based API (such as REST).
In scope:

- Cross-site request forgery (CSRF)
- Cross-site scripting (XSS)
- Authentication of users using a web browser
- Authentication of API calls
- Theft or exposure of authentication credentials

These are the areas of web security that can be at least partly addressed by a centralized authentication and security layer.
(For the Rubin Science Platform, that layer is provided by `Gafaelfawr`_ plus an NGINX ingress controller.)

.. _Gafaelfawr: https://gafaelfawr.lsst.io/

Traditionally part of web security, but out of scope for this document, are security problems specific to an application's development process or handling of user input that are difficult to address with a security layer.
Those out-of-scope topics include:

- SQL injection
- Arbitrary code execution for authenticated users
- Other user input handling errors, such as insecure deserialization
- Vulnerability management and third-party dependencies (see `SQR-042`_ for some discussion)
- Logging and monitoring

.. _SQR-042: https://sqr-042.lsst.io/

However, the narrow topic of protecting web access to applications within the Rubin Science Platform from a compromise of a single Science Platform application is in scope insofar as it can be addressed through good credential management practices and effective use of separate JavaScript origins.

The Rubin Science Platform is different than most web applications in that it intentionally offers its users remote code execution as a service via the Notebook Aspect.
Authenticated users are therefore expected to have considerable latitude in what actions they can perform.
The focus of this discussion is therefore on:

- Preventing unauthenticated access
- Preventing credential theft or hijacking (such as via CSRF)
- Protecting Rubin Science Platform users from malicious activity by other users
- Isolating services from each other to provide some defense in depth against security vulnerabilities in Science Platform services

Glossary
--------

Cross-site request forgery (CSRF)
    An attack that tricks the user into sending a malicious request on the attacker's behalf.
    The most obvious mechanism to do this is cross-site ``GET`` or ``POST`` requests triggered by JavaScript run on a malicious site to which the user went in a web browser, although there are other mechanisms.
    CSRF generally exploits the browser's security model to trick the browser into sending credentials that it has stored for its user (such as cookies) along with a request that is controlled by the attacker.

Cross-site scripting (XSS)
    An attack that involves injecting malicious content (usually JavaScript or CSS, although there are other possibilities) into a trusted web site, such as through untrusted user input that is displayed unescaped to other users.
    The malicious code then runs within the security context of the trusted site and can access the user's stored authentication credentials for that site, allowing it to take actions on behalf of the user, steal the credentials, or take other malicious actions.

Threat model
============

The expected goals of an attacker targeting the Science Platform are primarily the standard goals for general Internet attackers:

- Theft of compute resources (Bitcoin mining, bot networks)
- Extortion via ransomware (CryptoLocker)
- Web site hosting for further phishing or malware distribution
- Theft of valuable personal data (of which there is very little on the Rubin Science Platform)

The observatory data accessible via the Science Platform, while not all public, is of limited financial or strategic value to sophisticated attackers.
While the Science Platform will hold some limited personal information for its users, it will not contain stores of valuable personal or commercial data.
Unpublished astronomical research, while confidential, does not have the same appeal to attackers.
Therefore, targeted attacks by sophisticated attackers looking for data of monetary or political value are unlikely.

By design, the Rubin Science Platform is open to a broad array of scientists.
Authentication will be done via federated identity, removing the risk of storing and managing user passwords or other authentication credentials but increasing the risk of a user account compromise due to a compromise of some external authentication system outside of the control of Rubin Observatory.
We therefore expect incidents where the account of a legitimate user of the Rubin Science Platform will be compromised, and want to provide some protection to other users of the platform against malicious activity from a compromised account.

The individual applications that make up the Rubin Science Platform will be written by a variety of people and institutions with varying levels of attention to security.
Therefore, we do not want to treat all applications contained in the Rubin Science Platform as equally trustworthy.

The implication for web security is to focus efforts on providing a robust authentication layer, trust domain isolation between applications, and protection against typical XSS and CSRF attacks that an attacker might easily discover with an automated tool.

For considerably more discussion of the threat model, see `SQR-041`_.

.. _SQR-041: https://sqr-041.lsst.io/

Authentication
==============

The Rubin Science Platform uses opaque bearer tokens for authentication.
Each token is associated with a list of scopes, which restrict what services that token can be used to access.
See `SQR-044`_ for the identity management requirements, including access tokens, and `SQR-049`_ for the token system design.
`SQR-039`_ has some additional history and discussion.

.. _SQR-044: https://sqr-044.lsst.io/
.. _SQR-049: https://sqr-049.lsst.io/
.. _SQR-039: https://sqr-039.lsst.io/

As much as possible, authentication for applications in the Rubin Science Platform will be handled at the ingress layer of Kubernetes, before the external request reaches the application.
The underlying application can then be authentication-agnostic (if it doesn't need to make internal API calls on behalf of the user and doesn't need the user's identity), or can have a very simple authentication layer where it trusts user metadata and tokens that are passed to it in HTTP headers.

`Gafaelfawr`_ implements this authentication layer and supports passing user metadata and delegated access tokens to applications via HTTP headers.

Access control
--------------

Access control is done by scope.
Each meaningful domain of access must be assigned a unique scope in the configuration of the authentication system.
This needs to capture not only the granularity of user access permissions (for example, whether a given user is allowed to access a specific application), but also the granularity of service-to-service API calls.
Restricting the scope of delegated tokens passed to applications limits the damage that can be done by a compromised application.

Configuration
-------------

In this design, the authentication configuration of a given application is contained in its Kubernetes ``Ingress`` resource.
Annotations on that resource are read by the NGINX ingress controller and used to construct a subrequest to Gafaelfawr to make an access control decision for a given request.

The necessary configuration can be fairly complex, including:

- The required scopes to allow access
- Whether to create a delegated token for this user
- The scopes of the delegated token, if created
- Whether this is the notebook service (which requires some special token handling)
- Where (and if) to redirect the user to authenticate if they are not authenticated
- If not redirecting the user, whether to present a bearer challenge or a basic auth challenge (the UI of some applications may prefer a basic auth challenge to make ad hoc API calls via a web browser easier)
- Which user metadata headers to send to the application
- Whether to put the delegated token in an ``Authorization`` header
- Whether to allow cookie authentication
- Whether to prohibit ``POST`` with form submission ``Content-Type`` values
- What ``Content-Security-Policy`` header to add, if any

This can all be managed with manually-written NGINX ingress annotations with each service, with many of the parameters embedded in the ``auth-url`` URL, but this is tedious and error-prone.

We therefore plan to implement a custom Kubernetes resource that specifies a Gafaelfawr-protected resource, and a custom resource controller that writes the ``Ingress`` resource based on that custom resource.
This will allow the above information to be expressed in more human-readable YAML or derived from the cluster Gafaelfawr configuration.

Credential isolation
--------------------

The incoming request from a user may contain an access token in one of two places: an encrypted cookie that is read by Gafaelfawr, or in the ``Authorization`` header.
Because the underlying application should not be fully trusted, we do not want to pass the incoming cookie or token directly to the application, since this would allow a compromised application to act as the user with the full scope of the original cookie (which may have that user's full scope of access).
The incoming authentication credential must be filtered out of the request before it is passed to the backend service.

For backend services that need to make calls on behalf of the user, a new token specific to that service will be issued dynamically, with only the scopes that service needs, and passed to the service via an HTTP header.

For options on how to implement this, and some further discussion, see `SQR-051`_.
The recommended approach is to filter out incoming cookies by replacing the ``Cookie`` header with a rewritten header and replacing or dropping the ``Authorization`` header.

.. _SQR-051: https://sqr-051.lsst.io/

Logging
-------

Because authentication and access control is done via a generic layer in front of all applications, it can log all authenticated operations and maintain data about how tokens are used.
This, in turn, will be used to investigate possible security incidents and to look for anomolies in how tokens are used (such as use from an unexpected IP address).

Isolation
=========

Web security is closely tied to origins, which are (roughly) defined as the tuple of protocol, hostname, and port.
All JavaScript running on the same origin (including any URL path in that origin) has effectively the same privileges, can freely make HTTP requests of any type to other URLs on the same origin, can access any local state tied to that origin, and so forth.

Cookies have a similar concept called a site, which controls when the browser will send the cookie alongside a request.
The site of a cookie is somewhat less restricted than a JavaScript origin and can include subdomains depending on the cookie configuration.

The effect of this security model is that it is not possible to secure web applications against malicious JavaScript running in the same origin.
To isolate one web application from another, they must run in separate origins.

The easiest way to do this is to give every application a separate origin, usually by changing the hostname.
In the case of the Science Platform, this would mean assigning a separate hostname to every application, and then using either multiple TLS certificates, a wildcard TLS certificate, or a TLS certificate with multiple :abbr:`SANs (Subject Alternative Names)`.

However, separate origins are only crucial for web applications that run JavaScript in the browser.
REST API endpoints can safely share the same origin provided that they do not need to support cross-origin requests, do not serve pages or JavaScript that run in a web browser, and do not share an origin with a web application that does so.
Having all Science Platform REST APIs share the same origin is useful for documentation purposes and allows more flexibility about which API endpoints are served by which backend implementations.

Therefore, the isolation plan for the Rubin Science Platform is:

- Serve the Notebook Aspect spawning interface from its own origin
- Serve each user's notebook from a per-user origin (see :ref:`jupyterlab-origin`)
- Serve the Portal Aspect from its own origin
- Serve the authentication system from its own origin
- Serve all APIs from a single origin shared by the APIs, but separate from the other origins

Pure APIs (ones that are not part of a web browser UI and do not serve any JavaScript, CSS, or other similar content) can share a single origin as long as it is separate from all UI origins.
This is true even if some of the API backend servers are untrusted.
No JavaScript will run from that origin, so there is no risk of same-origin attacks even between untrusted API backend servers.
We will hide incoming credentials from the backend servers and disable cookie authentication to such APIs, so there is also no need to put them in separate origins for credential management purposes.

This approach will require some additional complexity in the authentication process to transfer cookie-based web browser credentials from one origin to another.
See `SQR-051`_ for additional details.

.. _jupyterlab-origin:

JupyterLab origins
------------------

The web security documentation for JupyterHub recommends `using a separate subdomain for each user <https://jupyterhub.readthedocs.io/en/stable/reference/websecurity.html>`__.
We will follow this recommendation.

This will require serving notebooks using a wildcard certificate.
The plan is to use a wildcard certificate from Let's Encrypt, using the DNS solver to authenticate.

CSRF protection
===============

The most common cause of :abbr:`CSRF (Cross-Site Request Forgery)` problems is the complexity of the browser security model.
When a user visits a web page with a web browser, that page may load JavaScript to execute in the user's browser.
That JavaScript code is allowed to make additional HTTP requests, which are then performed by the user's browser as well.
By default, no credentials (cookies or headers) are included in those requests.
However, the JavaScript code can ask that the HTTP request be made with credentials.
In this case, the browser will include the user's cookies for the *destination* site in the request, even if the JavaScript making the request has no access to read those cookies.

Summary of security model
-------------------------

The rules for what happens during JavaScript requests are very complex and have evolved over time.
There are two parts to the security model: whether the browser will immediately send the request to the remote site or instead send an ``OPTIONS`` request first (this is called a *CORS preflight*), and whether the JavaScript initiating the request can see the response.
Here is a brief and incomplete summary of the rules:

#. All requests to the same origin are allowed and will not trigger a CORS preflight check.
   This is a key part of why it is not possible to defend web services against JavaScript served from the same origin.

#. Requests to a different origin will trigger a CORS preflight check *unless* all of the following conditions are true (plus some other, less relevant ones):

   - The request is a ``GET``, ``HEAD``, or ``POST``
   - The request does not send headers other than ``Accept``, ``Accept-Language``, ``Content-Language``, and ``Content-Type``
   - The ``Content-Type`` header, if set, is one of ``application/x-www-form-urlencoded``, ``multipart/form-data``, or ``text/plain``.

#. If a CORS preflight check is triggered, the request will only be allowed if the server returns success to the ``OPTIONS`` call and includes appropriate headers allowing this remote origin.

#. If the request is made with credentials, it may be sent without a CORS preflight check if it meets the above criteria.
   However, unless the response from the server includes an ``Access-Control-Allow-Credentials: true`` header, the response will be rejected and will not be accessible to the JavaScript code making the request.

See `Cross-Origin Resource Sharing on MDN`_ for a good high-level summary and the the `Fetch specification`_ for all of the details.

.. _Cross-Origin Resource Sharing on MDN: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
.. _Fetch specification: https://fetch.spec.whatwg.org/

In most cases, the Rubin Science Platform does not need to support cross-origin requests.
When different components need to talk to each other, those requests are normally made by the server, not by JavaScript executed in the web browser.
Use of the Portal Aspect from the Notebook Aspect is the one exception and is discussed in :ref:`notebook-portal`.

Application design
------------------

Where possible, Rubin Science Platform applications should not support cross-origin requests.
Doing so securely will require substantial additional effort, so if the same need can be met by making the request from the server using a delegated token, that approach is preferred.

Applications must follow the standard web application conventions of using appropriate HTTP verbs based on whether a request may change state.
In particular, ``GET`` must be reserved for read-only requests, and all requests that modify data or otherwise change state must use ``POST`` or another appropriate verb.

Unless required by a protocol that the application needs to implement, only applications indended for use via a web browser should accept ``POST`` with a ``Content-Type`` of ``application/x-www-form-urlencoded``, ``multipart/form-data``, or ``text/plain``.
APIs should instead require the body of a ``POST`` have a declared content type of ``application/json``, ``text/xml``, or some other value.
(In other words, the typical REST API should require JSON or XML request bodies and not support form-encoded request bodies.)
This forces a CORS preflight check for cross-origin ``POST`` requests, avoiding the problem where a ``POST`` from malicious JavaScript is sent with credentials and has an effect on the server even though the response is discarded by the web browser.

Applications designed for use with a web browser that accept form submissions should use normal CSRF prevention techniques, such as the `synchronizer token pattern`_:

.. _synchronizer token pattern: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern

Applications should respond with an error to any ``OPTIONS`` requests so that CORS preflight checks will always fail, with the exception of the Portal Aspect (see :ref:`notebook-portal`).

Authentication methods
----------------------

In general, users will authenticate to browser-based applications using a cookie and to APIs using an ``Authorization`` header.
However, since the authentication layer is shared, it supports both authentication mechanisms.
This can be useful for dual-purpose APIs used both via React browser UIs and via direct API calls, and for some cases where one may want to allow a service or other non-browser client to make authenticated requests to an application that is normally used within a web browser.
However, it increases the risk of CSRF because including an ``Authorization`` header in a request always forces a CORS preflight check, but asking for cookies to be included does not.

Therefore, the authentication layer will support configuration indicating whether a given application should support cookie authentication.
This can be disabled for pure APIs that aren't intended to be used via a JavaScript frontend.
When disabled, requests with cookies but no ``Authorization`` header will be denied by the authentication layer before reaching the application, providing defense in depth against problems with other CSRF protection mechanisms.

APIs that are also used by JavaScript frontends will continue to allow cookie-based authentication.

``Origin`` header
-----------------

If cookie authentication is used, the authentication layer will check for an ``Origin`` header sent with the request and ignore cookie authentication if that header is present, not null, and does not match the origin of the requested URL.
The browser will add the ``Origin`` header automatically to cross-origin (and some same-origin) requets, and it cannot be disabled in JavaScript.
This effectively disables cookie authentication for cross-site requests in browsers that support ``Origin``, although the above explicit configuration should also be used for defense in depth.

``POST`` content type
---------------------

Applications that do not intend to support form submission do not need to accept the ``POST`` requests that avoid CORS preflight checks (ones with a ``Content-Type`` of ``application/x-www-form-urlencoded``, ``multipart/form-data``, or ``text/plain``.
We can therefore reject such requests at the generic authentication layer and prevent them from ever reaching the application.
This relieves the application of having to check the ``Content-Type`` of the ``POST`` body and protects against overly-helpful framework libraries that may attempt to interpret ``POST`` bodies of the wrong content type.
This will be an optional per-application configuration option.

.. _notebook-portal:

Notebook Aspect to Portal Aspect calls
--------------------------------------

The exception to the general rule that the Rubin Science Platform does not need to support cross-origin requests is that the Notebook Aspect uses client-side JavaScript to display images from the Portal Aspect inside the Notebook Aspect UI.
As described in :ref:`jupyterlab-origin`, each Notebook Aspect user instance will run in its own origin, so this is a cross-origin request.
Furthermore, it is a cross-origin request without a simple list of allowed origins, since the origin for the Notebook Aspect is dynamic (based on the username).

The Portal Aspect therefore must reply to the ``OPTIONS`` request sent as the CORS preflight check by checking the ``Origin`` header to see if it matches the expected pattern of a Notebook Aspect user notebook origin.
If so, it must respond with success, coping the ``Origin`` value to the ``Access-Control-Allow-Origin`` response header and including ``Access-Control-Allow-Credentials: true`` in the response headers.
If the origin doesn't match a Notebook Aspect user notebook origin from the same instance, it should reply with an error.

Similarly, when replying to the subsequent actual request, the Portal Aspect must include ``Access-Control-Allow-Credentials: true`` in the response headers.

Unfortunately, this cannot be done in the generic authentication layer because the NGINX ingress doesn't support intercepting and delegating ``OPTIONS`` requests, and it cannot be done directly in the ingress because the NGINX ingress CORS support doesn't support dynamic validation of origins.
It will therefore need to be done in the Portal Aspect code itself.

XSS protection
==============

Cross-site scriptiong (XSS) is, in simplified terms, a security vulnerability that allows injecting untrusted content into web pages that are rendered by a browser.
If an attacker can arrange to run JavaScript (or even CSS) in a target user's browser in the context of a site to which that user is authenticated, the attacker can potentially take actions on behalf of the user, steal the user's data, or steal credentials for later use.

The primary defense against XSS is secure programming practices in the individual applications, such as use of HTML frameworks and libraries that automatically escape untrusted content so that it will not be executed by a browser.
However, there are some protections that can be added at the infrastructure level to prevent some categories of XSS.
This is done via the ``Content-Security-Policy`` header, which, if present in the headers of an HTML response from a web server, specifies restrictions on what that page can do.
This can include restricting what JavaScript it will execute and what CSS it will apply.

The ideal content security policy disables all loading of JavaScript, images, CSS, and fonts except from the same origin and known trusted origins (such as CDNs), and then requires subresource integrity be used for every resource that is loaded.
Subresource integrity means that each reference to an external object in the HTML, such as a JavaScript script, CSS style sheet, or image, is accompanied with the hash of the expected resource.
The browser will then reject the loaded resource and not execute it if it doesn't match the hash.

Using this restrictive of a policy requires a considerable amount of work for the application.
Many applications are unfortunately not designed to allow for a restrictive policy.
However, some policies can be applied more broadly as long as applications avoid some insecure HTML construction patterns.

Application design
------------------

Rubin Science Platform applications ideally should attempt to use the full restrictive policy as described above.
However, failing that, they should at least be designed to avoid inline JavaScript and inline styles.
Inline objects are the easiest to construct in an XSS attack, so blocking them makes XSS attacks considerably more difficult.

Applications should then add the following header to their responses::

    Content-Security-Policy: default-src https:

which will require all resources be loaded via HTTPS and disable unsafe inline objects of any type.

If the application serves all of its own resources and does not load resources from any external site, it should send this stronger header instead::

    Content-Security-Policy: default-src 'self'

If it does not use JavaScript at all, it can disable loading JavaScript with::

    Content-Security-Policy: default-src 'self'; script-src 'none'

Many other variations are possible; see `Content Security Policy`_ for more information.
In general, an application should disable as many types of resources as possible.
If it isn't using a type of resource, turning it off means it's not available as a potential vector of XSS.

.. _Content Security Policy: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

Adding CSP via the ingress
--------------------------

When the application is written internally by Rubin Observatory, there is no reson not to have it send its own ``Content-Security-Policy`` header.
However, sometimes we may deploy externally-written applications that can use a more restrictive content security policy but for whatever reason do not send the header.

For those applications, we will add a ``Content-Security-Policy`` header to all responses via the NGINX ingress configuration.

Implementation status
=====================

**Last updated: May 26, 2021**

Implemented:

- Scope-based access control via a generic authentication service
- Logging of all authenticated access

Not yet implemented:

- ``Ingress`` configuration via a custom resource and controller
- Credential isolation for ``Cookie`` or ``Authorization`` headers
- Separation of Science Platform applications into their own origins
- Per-user origins for Notebook Aspect user notebooks
- Configuration specifying whether to allow cookie authentication
- Disable cookie authentication for cross-origin requests
- Restrict content type of ``POST`` requests
- Cross-site security configuration for Notebook to Portal Aspect calls
- Adding ``Content-Security-Policy`` headers via the ingress
