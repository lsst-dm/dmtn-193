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
    The most obvious mechanism to do this is cross-site GET or POST requests triggered by JavaScript run on a malicious site to which the user went in a web browser, although there are other mechanisms.
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
- Exfiltration of confidential data (of which there is very little on the Rubin Science Platform)

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
- Whether this is the notebook service (which gets some special token handling)
- Where (and if) to redirect the user to authenticate if they are not authenticated
- If not redirecting the user, whether to present a bearer challenge or a basic auth challenge (the UI of some applications may prefer a basic auth challenge to make ad hoc API calls via a web browser easier)
- Which user metadata headers to send back to the application
- Whether to put the delegated token in an ``Authorization`` header

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
- Serve each user's notebook from a per-user origin (see `jupyterlab-origin`_)
- Serve the Portal Aspect from its own origin
- Serve the authentication system from its own origin
- Serve all APIs from a single origin shared by the APIs, but separate from the other origins

This approach will require some additional complexity in the authentication process to transfer cookie-based web browser credentials from one origin to another.
See `SQR-051`_ for additional details.

.. _jupyterlab-origin:

JupyterLab origins
------------------

The web security documentation for JupyterHub recommends `using a separate subdomain for each user <https://jupyterhub.readthedocs.io/en/stable/reference/websecurity.html>`__.
We will follow this recommendation.

This will require serving notebooks using a wildcard certificate.
The plan is to use a wildcard certificate from Let's Encrypt, using the DNS solver to authenticate.
