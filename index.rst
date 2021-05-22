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
- Exfiltration of confidential data such as password databases

Additionally, since Rubin Observatory is prominent (receives news media coverage) and is associated with the US government, some attackers may want to embarrass Rubin Observatory or claim credit for hacking a well-known site.
Those attackers are likely to attempt web site defacement or release of non-public data that would embarrass Rubin Observatory or its sponsors.

The observatory data accessible via the Science Platform, while not all public, is of limited financial or strategic value to sophisticated attackers.
While the Science Platform will hold some limited personal information for its users, it will not contain stores of valuable personal or commercial data.
Unpublished astronomical research, while confidential, does not have the same appeal to attackers.
Therefore, targeted attacks by sophisticated attackers looking for data of monetary or political value are unlikely.

By design, the Rubin Science Platform is open to a broad array of scientists.
Authentication will be done via federated identity, removing the risk of storing and managing user passwords or other authentication credentials but increasing the risk of a user account compromise due to a compromise of some external authentication system outside of the control of Rubin Observatory.
We therefore expect incidents where the account of a legitimate user of the Rubin Science Platform will be compromised, and want to provide some protection to other users of the platform against malicious activity from a compromised account.

The individual applications that make up the Rubin Science Platform will be written by a variety of people and institutions with varying levels of attention to security.
Therefore, we do not want to treat all applications contained in the Rubin Science Platform as equally trustworthy.
Given the possibility of compromise of 

The implication for web security is to focus efforts on providing a robust authentication layer, isolation between applications, and protection against typical XSS and CSRF attacks that an attacker might easily discover with an automated tool.

For considerably more discussion of the threat model, see `SQR-041`_.

.. _SQR-041: https://sqr-041.lsst.io/
