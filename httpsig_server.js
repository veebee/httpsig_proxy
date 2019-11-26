const fs = require('fs');
const https=require('https');
const http=require('http');
const httpSignature=require('http-signature'); // git clone https://github.com/joyent/node-http-signature.git
const bodyParser=require('body-parser');
const conf=require('./httpsig_server_conf.json');
const crypto = require('crypto');
const util = require('util')


http.createServer(onRequest).listen(3000);
console.log('Listening on port 3000');

function onRequest(req,res)
{
  var body="";
  req.on('data',chunk => {
    body+=chunk.toString('utf-8'); // todo : detect encoding from req
  });
  req.on('end',() => {
    //console.log(util.inspect(req));

    var headers = req.headers;


    // prints out information
    console.log('Received sign request for data:');
    console.log('--------------------');
    console.log(headers);
    console.log('--------------------');
    console.log(body);
    console.log('--------------------');
    console.log('Destination host:');
    console.log(headers.host);
    console.log('URL:');
    console.log(req.url);
    console.log('QWAC key:'+conf.qwac_key);
    console.log('============================================');

    console.log("Headers Before : "+JSON.stringify(headers, null, 4));
    generateBGSignature(headers,body);
    console.log("Headers After  : "+JSON.stringify(headers, null, 4));

    var options = {
      host: headers.host,
      //host: '127.0.0.1',
      port: 443,
      path: req.url,
      method: req.method,
      headers: headers,
      key: fs.readFileSync(conf.qwac_key),
      cert: fs.readFileSync(conf.qwac_cert),
    };

    var remotereq=https.request(options, remoteres => {
      var responsebody="";
      remoteres.on('data', responsechunk => {
        responsebody+=responsechunk.toString('utf-8');
      });
      remoteres.on('end', () => {
        res.writeHead(remoteres.statusCode,remoteres.headers);
        res.end(responsebody);
      });
    });
    remotereq.on('error', e => {
      console.error(e);
    });

    remotereq.end(body);

  })
}




// not from luxhub
//  var key=fs.readFileSync(conf.qseal_key,'ascii');
//	httpSignature.sign(req, {
//	  key: key,
//  	keyId: conf.qseal_cert
//	});

/*
    try {
      var remoteRequest = https.request(options, function(remoteResponse) {
        console.log('Response received:'+remoteResponse.statusCode);

        res.status(200).send('Hello');
        console.log('After res.send');
      });
      remoteRequest.end();
      console.log('Request sent:'+req.output);

    } catch (e) {
      console.log("Exception caught : "+e);
    }
*/





// HTTP Signature function from develooper.luxhub.com
function generateBGSignature(headers, body) {
    // added for compilation
    let QSEALCert=fs.readFileSync(conf.qseal_cert,'ascii');
    let QSEALKey=fs.readFileSync(conf.qseal_key,'ascii');

    // Luxhub code starts here
    let headerCert = QSEALCert.replace(/\r/g, '');
    headerCert = headerCert.replace(/\n/g, '');
    headerCert = headerCert.replace(/-----[^ ]+ CERTIFICATE-----/g, '');
    headers["TPP-Signature-Certificate"] = headerCert;

    const {
        Certificate
    } = require('@fidm/x509');
    const cert = Certificate.fromPEM(QSEALCert);

    const digest = "SHA-256=" + crypto.createHash('sha256').update(body).digest('base64');
    let signingString = "digest: " + digest + "\n" +
        "x-request-id: " + headers["x-request-id"] + "\n" +
        "date: " + headers["date"];

    let signatureHeaders = "Digest X-Request-ID Date";

    if (typeof headers["psu-id"] !== "undefined") {
        signingString += "\npsu-id: " + headers["psu-id"];
        signatureHeaders += " psu-id";
    }

    if (typeof headers["psu-corporate-id"] !== "undefined") {
        signingString += "\npsu-corporate-id: " + headers["psu-corporate-id"];
        signatureHeaders += " psu-corporate-id";
    }

    if (typeof headers["tpp-redirect-uri"] !== "undefined") {
        signingString += "\ntpp-redirect-uri: " + headers["tpp-redirect-uri"];
        signatureHeaders += " tpp-redirect-uri";
    }

    headers["Digest"] = digest;
    let issuer=cert.issuer;
    headers["Signature"] = 'keyId="' + getBgKeyId(cert)+'"'+
        // not working
        //+ this.getCertificateIssuerValues(cert.issuer) +
        ", algorithm=\"rsa-sha256\"" +
        ", headers=\"" + signatureHeaders + "\"" +
        ", signature=\"" + crypto.createSign('SHA256').update(signingString).sign(QSEALKey, 'base64') + "\"";

    console.log("Signing4:"+signingString);
    return headers;
}

function getBgKeyId(cert)
{
  var S="SN="+cert.serialNumber+", CA=";
  for(let i=cert.issuer.attributes.length-1;i>=0;i--)
  {
    // console.log(JSON.stringify(cert.issuer.attributes[i]));
    let attr=cert.issuer.attributes[i];
    S=S+attr.shortName+"="+attr.value;
    if(i>0) S=S+",";
  }

  console.log(S);
  return(S);
}
