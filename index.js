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
    * Required parameters:
    *
    * certificate_request: the CSR bytes to be signed in PEM
    *
    * Optional parameters:
    * hosts: an array of SAN (subject alternative names) which overrides the ones in the CSR
    * subject: the certificate subject which overrides the ones in the CSR
    * serial_sequence: a string specify the prefix which the generated certificate serial should have
    * label: a string specifying which signer to be appointed to sign the CSR, useful when interacting with a remote multi-root CA signer
    * profile: a string specifying the signing profile for the signer, useful when interacting with a remote multi-root CA signer
    * bundle: a boolean specifying whether to include an "optimal" certificate bundle along with the certificate
    *
    */
  async sign(certificate_request, hosts=[], subject={}, serial_sequence="", label="", profile="", bundle=false, self=this) {
    return new Promise((resolve, reject) => {
      // if (params.hosts && params.hosts.length > 0) params.hosts = hosts
      // if (params.subject && params.subject.length > 0) params.subject = [subject]
      // if (params.serial_sequence && params.serial_sequence.length > 0) params.serial_sequence = serial_sequence
      // if (params.label && params.label.length > 0) params.label = label
      // if (params.profile && params.profile.length > 0) params.profile = profile
      // if (params.bundle && params.bundle.length > 0) params.bundle = bundle

      let params = {
        certificate_request,
        hosts,
        subject,
        serial_sequence,
        label,
        profile,
        bundle
      }

      self._client.post(self._apiPath("/sign"), self._authParams(params), (err, req, res, obj) => {
        if (err) return reject(err)
        return resolve(obj.result)
      })
    })
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
  * Alias for health function which only results a boolean
  *
  * @return {Boolean} Returns true or false
  */
 async isHealthy() {
  try {
    const result = await this.health()
    return result.healthy
  } catch (err) {
    return false
  }
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
  async certinfo(certificate, remote_domain="", serial="", authority_key_id="", self=this) {
    return new Promise((resolve,reject) => {
      let params = {
        certificate,
        remote_domain,
        serial,
        authority_key_id
      }
      if (!params.certificate) throw new Error("Missing certificate object")

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
  * Required parameters:
  * request: a json object specifying the certificate request, 
  *          exactly the one which can be sent to /api/v1/cfssl/newkey 
  *          to generate a certificate signing request 
  *          (referring to endpoint_newkey for how to write such object)
  *
  * Optional parameters:
  * label: a string specifying which signer to be appointed to sign
  *        the CSR, useful when interacting with cfssl server that stands
  *        in front of a remote multi-root CA signer
  * profile: a string specifying the signing profile for the signer
  * bundle: a boolean specifying whether to include an "optimal"
  *         certificate bundle along with the certificate
  *
  * Result:
  * The returned result is a JSON object with four keys:
  *
  * private key: a PEM-encoded private key
  * certificate_request: a PEM-encoded certificate request
  * certificate: a PEM-encoded certificate, signed by the server
  * sums: a JSON object holding both MD5 and SHA1 digests for the certificate
  *       request and the certificate; note that this is the digest of the DER
  *       contents of the certificate, not the PEM contents
  * bundle: See the result of endpoint_bundle.txt (only included if the bundle parameter was set)
  * 
  */
  async newcert(request, label="", profile="", bundle=false, self=this) {
    return new Promise((resolve,reject) => {
      // Massage the request a bit
      if (request.hosts && !isArray(request.hosts)) request.hosts = [request.hosts]
      if (request.names && !isArray(request.names)) request.names = [request.names]
      if (!request.names || request.names == 0) throw new Error("Missing names in request object")
      if (!request.CN || request.CN.length == 0) throw new Error("Missing CN in request object")

      let params = {
        request: request,
        label: label,
        profile: profile,
        bundle: bundle
      }

      self._client.post(self._apiPath("/newcert"), self._authParams(params), (err, req, res, obj) => {
        if (err) return reject(err)
        // if (!obj.success) return reject()
        return resolve(obj.result)
      })
    })
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

module.exports = CFSSL