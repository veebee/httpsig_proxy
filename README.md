# httpsig_proxy
NodeJS proxy implementing HTTP Signature.

The proxy listens to a pre-configured port, on clear-text traffic. It retrieves the destination from the "Host" header and forwards the call using:
- HTTPS (with mutual authentication/MTLS);
- HTTP Signature headers.

The paths to the certificates and keys must be defined in the config.json file, located under the config folder.

## Installation and deployment
### Pre-requisites
- Keys and certificates are properly listed under the config.json file;
- NodeJS and NPM are available on the host;
- There is Internet access on the host;
- The configured port (default 3000) is available.
### Installation and deployment
The process for deploying the application is straightforward:

    npm install
    node src/server.js

## Docker strategy
The proxy can also be deployed in a Docker container, using the Dockerfile provided in the repository.
### Pre-requisites
- Docker is available on the host, and the Docker daemon is running;
- The current folder is the main (top) folder from the repository;
### Building the image
Simply run a docker build as follows:

    docker build -t <your-username>/httpsig_proxy .
### Running the image
    docker run -p <configured-port> -d <your-name>/httpsig_proxy
