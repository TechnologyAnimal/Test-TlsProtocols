# Introduction 
Major browsers will drop support for TLS 1.1 by March 31, 2020. I needed a way to audit supported TLS protocols on both internal and external systems.
This function will output the SSL/TLS protocols that the client is able to successfully use to connect to a server using fqdn or ip.
This function can also be used to output remote certification information, such as thumbprint, subject, issuer, issue date and expiration data.
This function can also be used to export remote certificates in .cer format to a local filesystem.

# Getting Started
You can have this code up and running on your system in just a few moments. This can be accomplished in multiple ways:
1.	Install-Module -Name Test-TlsProtocols
2.	git clone https://github.com/TechnologyAnimal/Test-TlsProtocols.git
3.	[Direct Download](https://github.com/TechnologyAnimal/Test-TlsProtocols/archive/master.zip)
4.  Coming Soon: docker pull technologyanimal/test-tlsprotocols:latest

# Build and Test
All tests are written using the Pester Test Framework. To execute the tests yourself, run 'Install-Module Pester' and then 'Invoke-Pester'.

# Contribute
I will gladly merge any pull requests that contributes useful features or improves code quality. Some examples could be:
- Add more pester tests
- Identify cipher suites
- Check enabled SSL/TLS protocols that are enabled on the client
- Allow user to toggle RemoteCertificateValidationCallback on or off
- Add runspaces to support concurrent process threads in Powershell Version <7

# Read About TLS
If you want to learn more about TLS, here are some great resources:
- [TLS 1.3 - RFC8446](https://tools.ietf.org/html/rfc8446)
- [TLS 1.3 - Everything you need to know](https://www.thesslstore.com/blog/tls-1-3-everything-possibly-needed-know)
- [TLS 1.2 - RFC5246](https://tools.ietf.org/html/rfc5246)
- [SSL Stream](https://docs.microsoft.com/en-us/dotnet/api/system.net.security.sslstream?view=netcore-3.1#remarks)
