# SAMLResource
A extension to wrap the Security Assertion Markup Language Library (SAML) for Java.

**This Extension is provided as-is and without warranty or support. It is not part of the PTC product suite and there is no PTC support.**

## Description
This extension adds a Resource object wrapping the the Security Assertion Markup Language Library (SAML) for Java.

## Services
- *parseAssertion*: validates an assertion
  - input
    - xml: The XML document to validate - XML
  - output: BOOLEAN
- *validateAssertion*: parses an assertion
  - input
    - xml: The XML document to parse - XML
  - output: INFOTABLE (ds_SAMLAttributes, see below)

## DataShapes
- ds_SAMLAttributes
  - userID - STRING
  - firstName - STRING
  - lastName - STRING
  - email - STRING
  - role - STRING

## Configuration Tables
- X509CertificateParameters
  - X509Certificate: The X509 Certificate - STRING

## Dependencies
  - OneLogin's SAML Java Toolkit - [link](https://github.com/onelogin/java-saml)

## Donate
If you would like to support the development of this and/or other extensions, consider making a [donation](https://www.paypal.com/donate/?business=HCDX9BAEYDF4C&no_recurring=0&currency_code=EUR).
