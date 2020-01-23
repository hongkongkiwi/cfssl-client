/* External Modules */
const _ = require("lodash")
const restify = require("restify-clients")
/* Build in methods */
const crypto = require('crypto')
const path = require('path')
const querystring = require('querystring')
/* Useful Validation Methods */
const isIp = require('is-ip')
const isRegex = require('is-regex')
const isArray = _.isArray
const isUndefined = _.isUndefined
const has = _.has
const isEmpty = _.isEmpty
const extend = _.extend
const isPlainObject = _.isPlainObject

class CFSSL {
  KEY_USAGES = {
    SIGNING: "signing",
    DIGITAL_SIGNATURE: "digital signature",
		CONTENT_COMMITMENT: "content committment",
    KEY_ENCIPHERMENT: "key encipherment",
    KEY_AGREEMENT: "key agreement",
    DATA_ENCIPHERMENT: "data encipherment",
    CERT_SIGN: "cert sign",
		CRL_SIGN: "crl sign",
    SERVER_AUTH: "server auth",
    CLIENT_AUTH: "client auth",
    ENCIPHER_ONLY: "encipher only",
		DECIPHER_ONLY: "decipher only"
  }

  EXT_KEY_USAGES = {
    ANDY: "any",
		SERVER_AUTH: "server auth",
		CLIENT_AUTH: "client auth",
	  CODE_SIGNING: "code signing",
		EMAIL_PROTECTION: "email protection",
		SMIME: "s/mime",
		IPSEC_END_SYSTEM: "ipsec end system",
		IPSEC_TUNNEL: "ipsec tunnel",
		IPSEC_USER: "ipsec user",
		TIMESTAMPING: "timestamping",
		OCSP_SIGNING: "ocsp signing",
		MICROSOFT_SGC: "microsoft sgc",
		NETSCAPE_SGC: "netscape sgc"
  }

  BUNDLE_FLAVORS = {
    UBIQUITOUS: "ubiquitous", // A ubiquitous bundle is one that
                              // has a higher probability of being verified everywhere, even by
                              // clients using outdated or unusual trust stores.
    FORCE: "force",           // Force will cause the endpoint to use the bundle provided in the
                              // "certificate" parameter, and will only verify that the bundle
                              // is a valid (verifiable) chain.
    OPTIMAL: "optimal"
  }

  constructor(options) {
    this._options = extend({
      url: "http://localhost:8888",
      basePath: "/api/v1/cfssl",
      hmacKey: "",
      hmacAlgo: "sha256",
      certAttributes: {
        "C":  "US",
        "L":  "San Francisco",
        "O":  "Internet Widgets, Inc.",
        "OU": "WWW",
        "ST": "California"
      }
    }, options)
    
    this._client = restify.createJsonClient({
      url: this._options.url
    })
  }

  _authParams(params, key) {
    let newParams = params
    if (has(this._options, 'hmacKey') && this._options.hmacKey.length > 0 && 
        has(this._options, 'hmacAlgo') && this._options.hmacAlgo.length > 0) {
      newParams = {
        // this is a required field; it contains the computed authentication token.
        token: crypto.createHmac(this._options.hmacAlgo, this._options.hmacKey).update(JSON.stringify(params,null,0)).digest("base64"),
        // this is a required field; the JSON-encoded request being made.
        request: params,
        // an optional field containing a Unix timestamp. This might be used by an authentication provider; the standard authenticator does not use this.
        timestamp: Math.floor(Date.now() / 1000),
        // an optional field containing the address or hostname of the server; this may be used by an authentication provider. The standard authenticator does not use this field.
        remote_address: this._options.url
      }
    }
    return newParams
  }

  _apiPath(apiPath, queryStringParams) {
    apiPath = apiPath.substr(0,1) === "/" ? apiPath.substr(1) : apiPath
    apiPath = path.join(this._options.basePath, apiPath)
    if (isPlainObject(queryStringParams) && !isEmpty(queryStringParams, true)) {
      apiPath = apiPath + "?" + querystring.stringify(queryStringParams, "&", "=")
    }
    return apiPath
  }

  generateHMACKey(length) {
    length = parseInt(length) > 0 ? length : 32
    return crypto.randomBytes(length).toString('hex').toUpperCase()
  }

  // authenticated signing endpoint
  async authsign() {  
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

  // generates a CRL out of the certificate DB
  async crl() {

  }

  async revoke() {

  }

  async ocspsign() {

  }

  async gencrl() {
    
  }

  
  /**
  * Generate a new private key and certificate signing request
  *
  * @param {type} san_hosts       List of SANs (subject alternative names) for the
  *                               requested CSR (certificate signing request).
  * @param {type} cert_attributes Certificate subject for the requested CSR.
  * @param {type} common_name     Common name for the certificate subject in the requested CSR.
  * @param {type} key_config      Key algorithm and size for the newly generated private key default to ECDSA-256.
  * @param {type} ca_config       CA configuration of the requested CSR, including CA pathlen and CA default expiry
  *
  * @return {Object}              The returned result is a JSON object with three keys:
  *                               + private key: a PEM-encoded private key
  *                               + certificate_request: a PEM-encoded certificate request
  *                               + sums: a JSON object holding both MD5 and SHA1 digests for the certificate request
  */
  async newkey(san_hosts, cert_attributes, common_name, key_config, ca_config) {
    const self = this
    return new Promise((resolve,reject) => {
      if (!san_hosts || san_hosts.length === 0)
        return reject(new Error("Missing Parameters"))
      if (!isPlainObject(cert_attributes)) cert_attributes = self._options.certAttributes
      key_config = (isPlainObject(key_config) && has(key_config, [algo, size])) ? key_config : { "algo": "ecdsa", "size": 256 }
      // Coerce into array
      if (!isArray(san_hosts)) san_hosts = [san_hosts]

      let params = {
        hosts: san_hosts,
        names: [cert_attributes]
      }
      if (!isUndefined(common_name)) params.CN = common_name
      if (!isUndefined(key_config)) params.key = key_config
      if (!isUndefined(ca_config)) params.CA = ca_config

      self._client.post(self._apiPath("/newkey"), self._authParams(params), (err, req, res, obj) => {
        if (err) return reject(err)
        // if (!obj.success) return reject()
        return resolve(obj.result)
      })
    })
  }  

    /**
    * Sign a certificate
    *
    * The returned result is a JSON object with keys for each scan family. For
    * each family, there exists a `description` containing a string describing the
    * family and a `scanners` object mapping each of the family's scanners to
    * an object containing a `description` string.
    *
    * @since      x.x.x
    * @deprecated x.x.x Use new_function_name() instead.
    * @access     private
    *
    * @class
    * @augments parent
    * @mixes    mixin
    *
    * @alias    realName
    * @memberof namespace
    *
    * @see  Function/class relied on
    * @link URL
    * @global
    *
    * @fires   eventName
    * @fires   className#eventName
    * @listens event:eventName
    * @listens className~event:eventName
    *
    * @param {type}   var           Description.
    * @param {type}   [var]         Description of optional variable.
    * @param {type}   [var=default] Description of optional variable with default variable.
    * @param {Object} objectVar     Description.
    * @param {type}   objectVar.key Description of a key in the objectVar parameter.
    *
    * @yield {type} Yielded value description.
    */
  sign() {

  }

  /**
  * Build certificate bundles
  * 
  * One of the following two parameters is required; If both are
  * present, "remote_domain" becomes one of optional parameters with
  * "certificate", read on for details.
  *
  *
  *  If the "certificate" parameter is present, the following four
  *  parameters are valid:
  *
  *    + private_key: the PEM-encoded private key to be included with
  *      the bundle. This is valid only if the server is not running in
  *      "keyless" mode.
  *    + flavor: one of "ubiquitous", "force", or "optimal", with a
  *      default value of "ubiquitous". A ubiquitous bundle is one that
  *      has a higher probability of being verified everywhere, even by
  *      clients using outdated or unusual trust stores. Force will
  *      cause the endpoint to use the bundle provided in the
  *      "certificate" parameter, and will only verify that the bundle
  *      is a valid (verifiable) chain.
  *    + domain: the domain name to verify as the hostname of the certificate.
  *    + ip: the IP address to verify against the certificate IP SANs
  *
  *    If only the "domain" parameter is present, the following
  *    parameter is valid:
  *
  *    + ip: the IP address of the remote host; this will fetch the certificate
  *     from the IP, and verify that it is valid for the domain name.
  *
  * @param {type} certificate   The PEM-encoded certificate to be bundled.
  * @param {type} remote_domain A domain name indicating a remote host to retrieve a certificate for.
  *
  * @return {Object} Returns { healthy: true }
  */
  async bundle(certificate, remote_domain, private_key, flavor, domain, ip) {
    const self = this
    return new Promise((resolve,reject) => {
      let params = {}
      if (certificate) {
        params.certificate = certificate
        if (private_key) {
          params.private_key = private_key
        } else if (flavor) {
          params.flavor = flavor
        } else if (domain) {
          params.domain = domain
        } else if (ip) {
          params.ip = ip
        }
      } else if (remote_domain) {
        params.remote_domain = remote_domain
        if (ip) {
          params.ip = ip
        }
      } else {
        return reject(new Error("Must pass certificate or remote_domain"))
      }

      self._client.post(self._apiPath("/bundle"), self._authParams(params), (err, req, res, obj) => {
        if (err) return reject(err)
        // if (!obj.success) return reject()
        return resolve(obj.result)
      })
    })
  }

  /**
  * Check the health of the CA
  *
  * @return {Object} Returns { healthy: true }
  */
  async health() {
    const self = this
    return new Promise((resolve,reject) => {
      self._client.get(self._apiPath("/health"), (err, req, res, obj) => {
        if (err) return reject(err)
        // if (!obj.success) return reject()
        return resolve(obj.result)
      })
    })
  }


  /**
  * Get info about a certificate and the certificate itself
  *
  * @param {type} certificate         The PEM-encoded certificate to be parsed.
  * @param {type} [domain]            A domain name indicating a remote host to retrieve a certificate for.
  * @param {type} [serial]            A certificate serial to look for in the database, must pass together with authority_key_id
  * @param {type} [authority_key_id]  A matching authority key id to look for in the database, must pass together with serial
  *
  * @return {Object} The certinfo endpoint returns a JSON object with the following keys:
  *                  + subject contains a JSON object corresponding to a PKIX Name, including:
  *                   - common_name
  *                   - serial_number
  *                   - country
  *                   - organization
  *                   - organizational_unit
  *                   - locality
  *                   - province
  *                   - street_address
  *                   - postal_code
  *                   - names
  *                   - extra_names
  *                  + sans is a list of Subject Alternative Names.
  *                  + not_before is the certificate's start date.
  *                  + not_after is the certificate's end date.
  *                  + sigalg is the signature algorithm used to sign the certificate.
  */
  async certinfo(certificate, remote_domain, serial, authority_key_id) {
    const self = this
    return new Promise((resolve,reject) => {
      let params = {}
      if (certificate) {
        params.certificate = certificate
      } else if (remote_domain) {
        params.domain = remote_domain
      } else if (serial || authority_key_id) {
        params.serial = serial
        params.authority_key_id = authority_key_id
      } else {
        return reject(new Error("Must pass certificate, domain, or serial/authority_key_id"))
      }  

      self._client.post(self._apiPath("/certinfo"), self._authParams(params), (err, req, res, obj) => {
        if (err) return reject(err)
        // if (!obj.success) return reject()
        return resolve(obj.result)
      })
    })
  }

    // "CA": {
    //     "expiry": "127200h",
    //     "pathlen": 0
    // },

  // obtain information about the CA, including the CA certificate
  async info(label, profile) {
    const self = this
    return new Promise((resolve,reject) => {
      let params = {
        label: label
      }
      if (!isUndefined(profile)) {
        params.profile = profile
      }

      self._client.post(self._apiPath("/info"), self._authParams(params), (err, req, res, obj) => {
        if (err) return reject(err)
        // if (!obj.success) return reject()
        return resolve(obj.result)
      })
    })
  }

  // THE INFO ENDPOINT

  // Endpoint: /api/v1/cfssl/info
  // Method:   POST

  // Required parameters:

  //     * label: a string specifying the signer

  // Optional parameters:

  //     * profile: a string specifying the signing profile for the signer.
  //     Signing profile specifies what key usages should be used and
  //     how long the expiry should be set

  // Result:

  //     The returned result is a JSON object with three keys:

  //     * certificate: a PEM-encoded certificate of the signer
  //     * usage: a string array of key usages from the signing profile
  //     * expiry: the expiry string from the signing profile

  // Example:

  //     $ curl -d '{"label": "primary"}' \
  //           ${CFSSL_HOST}/api/v1/cfssl/info  \
  //           | python -m json.tool
  //   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
  //                                 Dload  Upload   Total   Spent    Left  Speed
  // 100   943  100   924  100    19  44029    905 --:--:-- --:--:-- --:--:-- 46200
  // {
  //     "errors": [],
  //     "messages": [],
  //     "result": {
  //         "certificate": "-----BEGIN CERTIFICATE-----\nMIICATCCAWoCCQDidF+uNJR6czANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJB\nVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0\ncyBQdHkgTHRkMB4XDTEyMDUwMTIyNTUxN1oXDTEzMDUwMTIyNTUxN1owRTELMAkG\nA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0\nIFdpZGdpdHMgUHR5IEx0ZDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAtpjl\nnodhz31kLEJoeLSkRmrv8l7exkGtO0REtIbirj9BBy64ZXVBE7khKGO2cnM8U7yj\nw7Ntfh+IvCjZVA3d2XqHS3Pjrt4HmU/cGCONE8+NEXoqdzLUDPOix1qDDRBvXs81\nKAV2qh6CYHZbdqixhDerjvJcD4Nsd7kExEZfHuECAwEAATANBgkqhkiG9w0BAQUF\nAAOBgQCyOqs7+qpMrYCgL6OamDeCVojLoEp036PsnaYWf2NPmsVXdpYW40Foyyjp\niv5otkxO5rxtGPv7o2J1eMBpCuSkydvoz3Ey/QwGqbBwEXQ4xYCgra336gqW2KQt\n+LnDCkE8f5oBhCIisExc2i8PDvsRsY70g/2gs983ImJjVR8sDw==\n-----END CERTIFICATE-----",
  //         "expiry": "8760h",
  //         "usages": [
  //             "signing",
  //             "key encipherment",
  //             "server auth",
  //             "client auth"
  //         ]
  //     },
  //     "success": true
  // }
  
  // initialise a new certificate authority
  async init_ca(san_hosts, ca_attributes, common_name, key_config, ca_config) {
    const self = this
    return new Promise((resolve,reject) => {
      if (!san_hosts || san_hosts.length === 0)
        return reject(new Error("Missing Parameters"))
      if (!isPlainObject(ca_attributes)) ca_attributes = self._options.certAttributes
      key_config = (isPlainObject(key_config) && has(key_config, [algo, size])) ? key_config : { "algo": "ecdsa", "size": 256 }
      // Coerce into array
      if (!isArray(san_hosts)) san_hosts = [san_hosts]

      let params = {
        hosts: san_hosts,
        names: [ca_attributes]
      }
      if (!isUndefined(common_name)) params.CN = common_name
      if (!isUndefined(key_config)) params.key = key_config
      if (!isUndefined(ca_config)) params.CA = ca_config

      self._client.post(self._apiPath("/init_ca"), self._authParams(params), (err, req, res, obj) => {
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
    })
  }

  /**
  * Generate a new private key and certificate
  *
  * @param {type} common_names      Certificate common names
  * @param {type} [cert_attributes] Certificate attributes
  * @param {type} [label]           A string specifying which signer to be appointed to sign the CSR, useful when interacting with cfssl server that stands.
  * @param {type} [profile]         A string specifying the signing profile for the signer.
  * @param {type} [includeBundle]   A boolean specifying whether to include an "optimal" certificate bundle along with the certificate.
  * 
  * @return {Object}  The returned result is a JSON object with four keys:
  *                   + private key: a PEM-encoded private key.
  *                   + certificate_request: a PEM-encoded certificate request.
  *                   + certificate: a PEM-encoded certificate, signed by the server.
  *                   + sums: a JSON object holding both MD5 and SHA1 digests for the certificate.
  *                   + request and the certificate; note that this is the digest of the DER.
  *                   + contents of the certificate, not the PEM contents.
  *                   + bundle: See the result of endpoint_bundle.txt (only included if the bundle parameter was set).
  */
  async newcert(common_names, cert_attributes, label, profile, includeBundle) {
    const self = this
    return new Promise((resolve,reject) => {
      if (!common_names || common_names.length === 0 || !cert_attributes)
        return reject(new Error("Missing Parameters"))

      if (!isArray(common_names))
        common_names = [common_names]
      if (!isArray(cert_attributes))
        cert_attributes = [cert_attributes]        

      let params = {
        hosts: common_names,
        names: cert_attributes
      }

      if (!isUndefined(label)) params.label = label
      if (!isUndefined(profile)) params.profile = profile
      if (!isUndefined(includeBundle)) {
        params.bundle = includeBundle
      } else {
        params.bundle = false
      }

      self._client.post(self._apiPath("/newcert"), self._authParams(params), (err, req, res, obj) => {
        if (err) return reject(err)
        // if (!obj.success) return reject()
        return resolve(obj.result)
      })
    })
    //   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
    //                                  Dload  Upload   Total   Spent    Left  Speed
    // 100  2487    0  2338  100   149  56536   3603 --:--:-- --:--:-- --:--:-- 57024
    // {
    //     "errors": [],
    //     "messages": [],
    //     "result": {
    //         "certificate": "-----BEGIN CERTIFICATE-----\nMIIDRzCCAjGgAwIBAgIIV2zafpyQtp4wCwYJKoZIhvcNAQELMIGMMQswCQYDVQQG\nEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNj\nbzETMBEGA1UEChMKQ0ZTU0wgVEVTVDEbMBkGA1UEAxMSQ0ZTU0wgVEVTVCBSb290\nIENBMR4wHAYJKoZIhvcNAQkBFg90ZXN0QHRlc3QubG9jYWwwHhcNMTUwODAzMDYx\nMjAwWhcNMTYwODAyMDYxMjAwWjBqMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLZXhh\nbXBsZS5jb20xFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEzARBgNVBAgTCkNhbGlm\nb3JuaWExGDAWBgNVBAMTD3d3dy5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqG\nSM49AwEHA0IABK/CtZaQ4VliKE+DLIVGLwtSxJgtUKRzGvN1EwI3HRgKDQ3l3urB\nIzHtUcdMq6HZb8jX0O9fXYUOf4XWggrLk1ajgZwwgZkwDgYDVR0PAQH/BAQDAgCg\nMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0G\nA1UdDgQWBBTF8UwoRdK0rWK8FWiyRxl3H2Wr+TAfBgNVHSMEGDAWgBS30veEuqg5\n1fusEM4p/YuWpBPsvTAaBgNVHREEEzARgg93d3cuZXhhbXBsZS5jb20wCwYJKoZI\nhvcNAQELA4IBAQCT+9xoBO39nFesT0dmdqpwHExU09/IYrkvYwWesX5U9z/f3HYP\nLz/NnXIs6a+k8MglvZgHwr5R8nzVtayfPTWyML6L6AOX8EfV5UXbnXW4XRUhHAik\n+E1gYhOCD1dLQJyQkX8VVr725BUk1yQD3Kf0PJUvagLJjn8Gn7QoGWfvVgpR8iMd\ncBJqlx8Z9KCYcLrpXliD8OJqT7Z8TGbnehpcaNwPPI6dMX57wgXSNuP5g8OkxMcL\nxZEP3q9JRjN3ZiM5xIeoTc/zl1WhZ+YpOHSbv/T9DX3f74ms9GEc0JnR8iENJTu6\nRx0/qPDPpqZ+Fr9v/13/OvQ+jAY5qe/6l1d6\n-----END CERTIFICATE-----\n",
    //         "certificate_request": "-----BEGIN CERTIFICATE REQUEST-----\nMIIBUjCB+QIBADBqMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLZXhhbXBsZS5jb20x\nFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEzARBgNVBAgTCkNhbGlmb3JuaWExGDAW\nBgNVBAMTD3d3dy5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\nBK/CtZaQ4VliKE+DLIVGLwtSxJgtUKRzGvN1EwI3HRgKDQ3l3urBIzHtUcdMq6HZ\nb8jX0O9fXYUOf4XWggrLk1agLTArBgkqhkiG9w0BCQ4xHjAcMBoGA1UdEQQTMBGC\nD3d3dy5leGFtcGxlLmNvbTAKBggqhkjOPQQDAgNIADBFAiAcvfhXnsLtzep2sKSa\n36W7G9PRbHh8zVGlw3Hph8jR1QIhAKfrgplKwXcUctU5grjQ8KXkJV8RxQUo5KKs\ngFnXYtkb\n-----END CERTIFICATE REQUEST-----\n",
    //         "private_key": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIJfVVIvXclN1jCWefEwhYYq7y1ya2RjxO5o8QjehD3YdoAoGCCqGSM49\nAwEHoUQDQgAEr8K1lpDhWWIoT4MshUYvC1LEmC1QpHMa83UTAjcdGAoNDeXe6sEj\nMe1Rx0yrodlvyNfQ719dhQ5/hdaCCsuTVg==\n-----END EC PRIVATE KEY-----\n",
    //         "sums": {
    //             "certificate": {
    //                 "md5": "E9308D1892F1B77E6721EA2F79C026BE",
    //                 "sha-1": "4640E6DEC2C40B74F46C409C1D31928EE0073D25"
    //             },
    //             "certificate_request": {
    //                 "md5": "AA924136405006E36CEE39FED9CBA5D7",
    //                 "sha-1": "DF955A43DF669D38E07BF0479789D13881DC9024"
    //             }
    //         }
    //     },
    //     "success": true
    // }
  }
  
  /**
  * Scan servers to determine the quality of their TLS set up 
  * 
  * @param {type} host      The hostname (optionally including port) to scan.
  * @param {type} [ip]      IP Address to override DNS lookup of host.
  * @param {type} [timeout] The amount of time allotted for the scan to complete (default: 1 minute).
  * 
  * The following parameters are used by the scanner to select which
  * scans to run.
  * @param {type} [family]  Regular expression specifying scan famil(ies) to run.
  * @param {type} [scanner] Regular expression specifying scanner(s) to run.
  * 
  * @return {Object} The returned result is a JSON object with keys for each scan family. Each
  *                  of these objects contains keys for each scanner run in that family pointing
  *                  to objects possibly containing the following keys:
  *
  *                  + grade: a string describing the exit status of the scan. Can be:
  *                   - "Good": host performing the expected state-of-the-art
  *                   - "Warning": host with non-ideal configuration, possibly maintaining support for legacy clients
  *                   - "Bad": host with serious misconfiguration or vulnerability
  *                   - "Skipped": indicates that the scan was not performed for some reason
  *                  + error: any error encountered during the scan process
  *                  + output: arbitrary JSON data retrieved during the scan
  */
  scan(host, ip, timeout, family, scanner) {
    const self = this
    return new Promise((resolve,reject) => {  
      let params = {
        host: host
      }
      if (!isUndefined(ip) && isIp(ip)) params.ip = ip
      if (!isUndefined(timeout)) {
        params.timeout = timeout 
      } else {
        params.timeout = "60s"
      }
      if (!isUndefined(family) && isRegex(family)) params.family = family
      if (!isUndefined(scanner) && isRegex(scanner)) params.scanner = scanner

      self._client.get(self._apiPath("/scan", params), (err, req, res, obj) => {
        if (err) return reject(err)
        // if (!obj.success) return reject()
        return resolve(obj.result)
      })
    })
  }

  /**
  * List options for scanning.
  *
  * @return {Object} The returned result is a JSON object with keys for each scan family. For
  *                  each family, there exists a `description` containing a string describing the
  *                  family and a `scanners` object mapping each of the family's scanners to
  *                  an object containing a `description` string.
  */
  scaninfo() {
    const self = this
    return new Promise((resolve,reject) => {
      self._client.get(self._apiPath("/scaninfo"), (err, req, res, obj) => {
        if (err) return reject(err)
        // if (!obj.success) return reject()
        return resolve(obj.result)
      })
    })
  }
}

const cfssl = new CFSSL()

cfssl.init_ca("www.example.com", [{"C":"US", "ST":"California", "L":"San Francisco", "O":"example.com"}]).then((result) => {
  console.log(result)
  //return cfssl.newcert("google.com", [{"C":"HK", "ST":"Hong Kong", "L":"Hong Kong", "O":"google"}])
  // return cfssl.info("primary")
  // return cfssl.scaninfo()
  // return cfssl.scan("www.google.com")
  // return cfssl.certinfo(null, 'www.google.com')
  return cfssl.health()
}).then((result) => {
  console.log(result)
}).catch((err) => {
  console.error(err)
})
