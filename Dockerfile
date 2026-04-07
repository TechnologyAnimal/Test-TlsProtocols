FROM mcr.microsoft.com/powershell:latest

LABEL maintainer="TechnologyAnimal" \
      description="Test-TlsProtocols - Audit SSL/TLS protocols and cipher suites" \
      version="2.1.0"

# Copy module into the PowerShell modules path
COPY Test-TlsProtocols/ /usr/local/share/powershell/Modules/Test-TlsProtocols/

ENTRYPOINT ["pwsh", "-Command"]
CMD ["Import-Module Test-TlsProtocols; Test-TlsProtocols -Server 'github.com' -ProtocolName 'Tls12', 'Tls13'"]
