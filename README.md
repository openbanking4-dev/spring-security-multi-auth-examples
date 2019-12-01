# Spring security multi auth examples

In this repo, we will show you examples of how to use the java library spring-security-multi-auth.
You can find the repo of the lib here [https://github.com/openbanking4-dev/spring-security-multi-auth](https://github.com/openbanking4-dev/spring-security-multi-auth).

We strongly recommend going though README of the lib first, as it gives you the context of when you should use this lib or not.

## Build the examples

You can use intellij to run those examples. We shared the run configurations.

If you wish to do a quick test, you can follow the steps:

1 - Build the project
```bash
mvn clean install
```

2 - Run the examples:

2 - a Example 1:
```bash
java -jar example1-cookie-and-api-token/target/spring-security-multi-auth-examples-example1-cookie-and-api-token-*.jar
```
2 - b Example 2:
```bash
java -jar example2-client-cert-and-access-token/target/spring-security-multi-auth-examples-example2-client-certs-and-access-token-*.jar
```

## How the examples are designed

We setup a spring security configuration, using the spring security multi-auth and we also expose an endpoint, 
which returns the identity and authorization of the user.
It's a simple `GET /whoAmI`.

The idea is that you can call this endpoints using different auth methods and see how your endpoint is identifying you.

## Example 1 - Cookie and API token

The first example shows you how to protect your API with both an API token and a cookie.
It's particularly useful if your front-end is consuming the same backend APIs then the third party developers.

### As anonymous
We basically don't send any form of credential

```bash
curl -k -X GET  https://localhost:8443/whoAmI
```

As a response:
```json
{
    "password": "",
    "username": "anonymous",
    "authorities": [],
    "accountNonExpired": true,
    "accountNonLocked": true,
    "credentialsNonExpired": true,
    "enabled": true
}
```


### With a cookie
We are now going to send a cookie. In the example, we decided to use a JWT cookie signed with HMAC.
The payload of our JWT will be:
```json
{
  "sub": "toto",
  "group": [
    "admin",
    "clubFalafelKing"
  ]
}
```
which contains the username and the authorities corresponding to this user.


```bash
curl -k -X GET  https://localhost:8443/whoAmI \
  -H 'Cookie: SSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3RvIiwiZ3JvdXAiOlsiYWRtaW4iLCJjbHViRmFsYWZlbEtpbmciXX0.954F4BxnEPjeWeKlzQ_AFUwRvtT1fVg5qBjA4zOdMkQ,SSO=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b3RvIiwiZ3JvdXAiOlsiYWRtaW4iLCJjbHViRmFsYWZlbEtpbmciXX0.954F4BxnEPjeWeKlzQ_AFUwRvtT1fVg5qBjA4zOdMkQ'
```

As a response:
```json
{
    "password": "",
    "username": "toto",
    "authorities": [
        {
            "authority": "admin"
        },
        {
            "authority": "clubFalafelKing"
        }
    ],
    "accountNonExpired": true,
    "accountNonLocked": true,
    "credentialsNonExpired": true,
    "enabled": true
}
```

### With an API token
This time, we are going to send an API token. We mock the actual token validation for this example and hard coded the API token
to the user `bob` with the authority `repo-42`.

```bash
curl -k -X GET  https://localhost:8443/whoAmI \
  -H 'key: 1NiIsInR5cCI6Ik'
```

As a response:
```json
{
    "password": "",
    "username": "bob",
    "authorities": [
        {
            "authority": "repo-32"
        }
    ],
    "accountNonExpired": true,
    "accountNonLocked": true,
    "credentialsNonExpired": true,
    "enabled": true
}
```

### Conclusion of example 1

In this example, we show you how to use a cookie and an api token at the same time, on the same endpoint. You can obviously choose to use one of them only.

## Example 2 Client certificate with an access token

In this example, we will show you how you can identify a request using the client certificate and retrieve the granted authorisations using an access token.
This example also shows you how to do token binding, meaning that you verify that the access token is associated with the client certificate received.
It is a security pattern that provide the proof of possession concept. This is in particular the security mechanism choose by Open Banking UK.

Note: we changed the port to 9443 for the example 2, so you can run both examples in parallel.

We took the architecture choice to consider that the SSL termination is most likely going to happen at the gateway level.
Therefore, the app will trust a header 'x-cert' that contains the client certificate in a PEM format.

### As anonymous
We basically don't send any form of credential

```bash
curl -k -X GET  https://localhost:9443/whoAmI
```

As a response:
```json
{
    "password": "",
    "username": "anonymous",
    "authorities": [],
    "accountNonExpired": true,
    "accountNonLocked": true,
    "credentialsNonExpired": true,
    "enabled": true
}
```

### With a client certificate and an access token

We are going to send an access token and a client certificate at the same time. 
In theory, the application should send the access token to validation to the Authorisation Server. In our case, we mock this by using 
a stateless access token signed using HMAC. In OAuth 2, you would call the introspection endpoint.

We are going to send this mock access token `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl0sImNuZiI6eyJ4NXQjUzI1NiI6ImMxYzRmMDUwZjFlMWVlYmVkZWM5ODdjZWI0YWI5OGUyYzgzZTY2NTNmNSJ9fQ.CGlP1iHs-xOwc5bOJz0u3ZZbU0TPGkP2cu-6HRkY5q8eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl0sImNuZiI6eyJ4NXQjUzI1NiI6ImMxYzRmMDUwZjFlMWJlZGVjOTg3Y2ViNGFiOThlMmM4M2U2NjUzZjUifX0.-4pfNjqXdkTcpiRieH09HIOMmE3mJF6zlksfocyXXAA`
What is interesting is to look at the JSON payload of this access token:

```JSON
{
  "scope": [
    "accounts",
    "payments"
  ],
  "cnf": {
    "x5t#S256": "c1c4f050f1e1bedec987ceb4ab98e2c83e6653f5"
  }
}
```

it contains the scope but also the thumbprint of the certificate, which is the one corresponding to the client cert we will send.



```bash
curl -k -X GET \
  https://localhost:9443/whoAmI \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl0sImNuZiI6eyJ4NXQjUzI1NiI6ImMxYzRmMDUwZjFlMWVlYmVkZWM5ODdjZWI0YWI5OGUyYzgzZTY2NTNmNSJ9fQ.CGlP1iHs-xOwc5bOJz0u3ZZbU0TPGkP2cu-6HRkY5q8eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJhY2NvdW50cyIsInBheW1lbnRzIl0sImNuZiI6eyJ4NXQjUzI1NiI6ImMxYzRmMDUwZjFlMWJlZGVjOTg3Y2ViNGFiOThlMmM4M2U2NjUzZjUifX0.-4pfNjqXdkTcpiRieH09HIOMmE3mJF6zlksfocyXXAA
  -H 'x-cert: -----BEGIN CERTIFICATE-----MIIDvzCCAqegAwIBAgIEcBt91TANBgkqhkiG9w0BAQsFADCBhjELMAkGA1UEBhMCR0IxDTALBgNVBAgTBEF2b24xEDAOBgNVBAcTB0JyaXN0b2wxGTAXBgNVBAoTEE9wZW5CYW5raW5nNC5kZXYxKzApBgNVBAsTIlNwcmluZy1zZWN1cml0eS1tdWx0aS1hdXRoLWV4YW1wbGUxDjAMBgNVBAMTBWFsaWNlMB4XDTE5MTIwMTE1NTIxM1oXDTIyMDMwNTE1NTIxM1owgYYxCzAJBgNVBAYTAkdCMQ0wCwYDVQQIEwRBdm9uMRAwDgYDVQQHEwdCcmlzdG9sMRkwFwYDVQQKExBPcGVuQmFua2luZzQuZGV2MSswKQYDVQQLEyJTcHJpbmctc2VjdXJpdHktbXVsdGktYXV0aC1leGFtcGxlMQ4wDAYDVQQDEwVhbGljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALZ/4eeNOvY8PFkr2LgrAB9pU0W3MtPXBuOpsKtPLpByWwxN8Ki5fRktzpCxMDtT7QJ9A0TrWuZ2J5R044iILfRLz+SfcClnimM5nH3iSd4DiBt5ve/VwdlNqzoqf/xCCBC4i4ygES9LLr9GIa+04Bkij6lFjqnKLumXg1U+g/TZnUVOlTu7HTYEBaFtHJCl44bk2zPGCsdkbKGyu08txPv50aCcgwb0VMA+IHY5KF2xbXh4UeOq7gRJkGTZNPJft3Ow8ROWz0VdvdGuanznaamUxiAawQrujRxUXgQUQlC2EpAruknsP9Hg5198BA1sgpMn9Jwgg1TOLuuWlYjeptkCAwEAAaMzMDEwHQYDVR0OBBYEFEgjYMV2dhr9Tn/U9zjvxGh7gNuPMBAGA1UdEQQJMAeCBWFsaWNlMA0GCSqGSIb3DQEBCwUAA4IBAQAjrLOmdYV0bJgYVx8An/wXl2+1Skq7rrqAufxYJRW2cSa6RiY11S+QOIEPC052bQdZo26BSUAPxxfVeNR0GPoIFl1BECdE/GHZdKtkfOqAvBJqSyNuVRdYC6ePhrEI/9Q3zIW2LDqhRfJuPgdVznCG3xw+LgZeb4Y1+7Lvd6PGxJOsdvP1mRInoH36fI+A/+lRfTsdb35QuRYX8XdkVnFs9ugu9adXM4W5NHbQZXzeM76MARfusezpdF011dFX3C45jArRUwjXwt/w8G7/ps1KMmHkhQ1MzxLRAiqtTWkWqnwxUMI8vxgLpyLLZNFMuJPESuhs3QOjqAj0A31vSiCd-----END CERTIFICATE-----'
```

As a response:
```json
{
    "password": "",
    "username": "alice",
    "authorities": [
        {
            "scopeName": "accounts",
            "authority": "SCOPE_accounts"
        },
        {
            "scopeName": "payments",
            "authority": "SCOPE_payments"
        }
    ],
    "accountNonExpired": true,
    "accountNonLocked": true,
    "credentialsNonExpired": true,
    "enabled": true
}
```

### Conclusion of example 2

Having two auth like client cert and access token is a good security design. It is encourage those days by different standards,
including OAuth 2.0 and Open Banking UK.
