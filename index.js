const _ = require('lodash')
const restify = require('restify-clients');

class CFSSL {
  constructor(options) {
    this._options = _.extend({
      url: 'http://localhost:8888',
      basePath: '/api/v1/cfssl'
    }, options)
    
    this._client = restify.createJsonClient({
      url: this._options.url
    })
  }

  // authenticated signing endpoint
  authsign() {  
    // THE AUTHENTICATED SIGNING ENDPOINT

    // Endpoint: /api/v1/cfssl/authsign
    // Method:   POST
    
    // Required parameters:
    
    //     * token: the authentication token
    //     * request: an encoded JSON signing request (e.g. as
    //            documented in endpoint_sign.txt).
    
    // Optional parameters:
    
    //     The following parameters might be used by the authenticator
    //     as part of the authentication process.
    
    //     * timestamp: a Unix timestamp
    //     * remote_address: an address used in making the request.
    //     * bundle: a boolean specifying whether to include an "optimal"
    //     certificate bundle along with the certificate
    
    // Result:
    
    //     The returned result is a JSON object with a single key:
    
    //     * certificate: a PEM-encoded certificate that has been signed
    //     by the server.
    //     * bundle: See the result of endpoint_bundle.txt (only included if the bundle parameter was set)
    
    // The authentication documentation contains more information about how
    // authentication with CFSSL works.

    const params = {
    }
  }
  // build certificate bundles
  bundle() {

  }
  // generates a CRL out of the certificate DB
  crl() {

  }
  // obtain information about the CA, including the CA certificate
  info() {
            "CA": {
                "expiry": "127200h",
                "pathlen": 0
            },
  }
  // initialise a new certificate authority
  init_ca(san_hosts, ca_attributes, common_name, key, ca_config) {
    const client = this._client
    const basePath = this._options.basePath
    return new Promise((resolve,reject) => {
      if (!san_hosts || san_hosts.length === 0 || !ca_attributes)
        return reject(new Error("Missing Parameters"))
      key = key ? key : { "algo": "ecdsa", "size": 256 }
      // Coerce into array
      if (!_.isArray(san_hosts))
        san_hosts = [san_hosts]

      let params = {
        hosts: san_hosts,
        names: ca_attributes
      }
      if (!_.isUndefined(common_name))
        params.CN = common_name
      if (!_.isUndefined(key))
        params.key = key
      if (!_.isUndefined(ca_config))
        params.CA = ca_config

      client.post(basePath + '/init_ca', params, (err, req, res, obj) => {
        if (err) return reject(err)
        // if (!obj.success) return reject()
        return resolve(obj.result)
      })

      // THE CA CERTIFICATE GENERATING ENDPOINT
      // Endpoint: /api/v1/cfssl/init_ca
      // Method:   POST
      
      // Required parameters:
      //     * hosts: the list of SANs (subject alternative names) for the
      //     requested CA certificate
      //     * names: the certificate subject for the requested CA certificate
      // Optional parameters:
      //     * CN: the common name for the certificate subject in the requested
      //     CA certificate.
      //     * key: the key algorithm and size for the newly generated private key,
      //     default to ECDSA-256
      //     * ca: the CA configuration of the requested CA, including CA pathlen
      //     and CA default expiry
      //     "CA": {
      //        "expiry": "127200h",
      //        "pathlen": 0
      //     },
      
      
      // Result:
      //     The returned result is a JSON object with three keys:
      //     * private key: a PEM-encoded CA private key
      //     * certificate: a PEM-encoded self-signed CA certificate
      
      // Example:
      //     $ curl -d '{"hosts":["www.example.com"], "names":[{"C":"US", "ST":"California", "L":"San Francisco", "O":"example.com"}], "CN": "www.example.com"}' \
      //           ${CFSSL_HOST}/api/v1/cfssl/init_ca  \
      //           | python -m json.tool
      
      //   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
      //                                  Dload  Upload   Total   Spent    Left  Speed
      // 100  1287  100  1152  100   135  36806   4313 --:--:-- --:--:-- --:--:-- 37161
      // {
      //     "errors": [],
      //     "messages": [],
      //     "result": {
      //         "certificate": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIHSuWpkTLyX4pucRtUATncQaTYtTRJNDpt8j7cnBeVceoAoGCCqGSM49\nAwEHoUQDQgAEqj9wJFCAqvcLRRB+qSc/jxLgUHLTMUi6ko/JupAWI1V5SjZxuL4u\nh6HS3VE4fvCdcfa06PAAKiJBNsfPBcS/Ig==\n-----END EC PRIVATE KEY-----\n",
      //         "private_key": "-----BEGIN CERTIFICATE-----\nMIICMDCCAdagAwIBAgIIOdP968SD1xgwCgYIKoZIzj0EAwIwajELMAkGA1UEBhMC\nVVMxFDASBgNVBAoTC2V4YW1wbGUuY29tMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2Nv\nMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRgwFgYDVQQDEw93d3cuZXhhbXBsZS5jb20w\nHhcNMTUwODAzMDYyODAwWhcNMjAwODAxMDYyODAwWjBqMQswCQYDVQQGEwJVUzEU\nMBIGA1UEChMLZXhhbXBsZS5jb20xFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEzAR\nBgNVBAgTCkNhbGlmb3JuaWExGDAWBgNVBAMTD3d3dy5leGFtcGxlLmNvbTBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABKo/cCRQgKr3C0UQfqknP48S4FBy0zFIupKP\nybqQFiNVeUo2cbi+Loeh0t1ROH7wnXH2tOjwACoiQTbHzwXEvyKjZjBkMA4GA1Ud\nDwEB/wQEAwIABjASBgNVHRMBAf8ECDAGAQH/AgECMB0GA1UdDgQWBBTH3jEBAIFt\nFFgJAI9lm8ktqxNt+DAfBgNVHSMEGDAWgBTH3jEBAIFtFFgJAI9lm8ktqxNt+DAK\nBggqhkjOPQQDAgNIADBFAiEA7s2UgPNJuQLzcXYNTQxhYqFq2+rbrJGC0WhYE8+r\n1yACIC5fsyyNNlw5HbSv4MDBwu3ozsMdfmoQTLVyijW/LC9r\n-----END CERTIFICATE-----\n"
      //     },
      //     "success": true
      // }
    })
  }
  // generate a new private key and certificate signing request
  newkey() {

  }
  // generate a new private key and certificate
  newcert() {

  }
  // scan servers to determine the quality of their TLS set up 
  scan() {

  }
  // list options for scanning
  scaninfo() {

  }
  // sign a certificate
  sign() {

  }
}

const cfssl = new CFSSL()
cfssl.init_ca('www.example.com', [{"C":"US", "ST":"California", "L":"San Francisco", "O":"example.com"}]).then((result) => {
  console.log(result)
}).catch((err) => {
  console.error(err)
})
