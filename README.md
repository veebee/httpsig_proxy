# httpsig_proxy
node.js proxy implementing HTTP Signature

application listens to port 3000 for HTTP (unsecured) traffic

application will get the destination from the "Host" header

application will forward the call to destination using
- HTTPS (with mutual authentication)
- HTTP Signature headers

All keys must be referenced in httpsig_server_conf.json (configuration file)
