const cfssl = new CFSSL()

cfssl.init_ca("www.example.com", [{"C":"US", "ST":"California", "L":"San Francisco", "O":"example.com"}]).then((result) => {
  // console.log(result)
  return cfssl.newcert({
    hosts: "google.com", 
    names: [{"C":"CN", "ST":"Blah", "L":"Blah", "O":"google"}],
    CN: "www.google.com"
  })

  // return cfssl.info("primary")
  // return cfssl.scaninfo()
  // return cfssl.scan("www.google.com")
  // return cfssl.certinfo(null, 'www.google.com')
  // return cfssl.health()
  // return cfssl.isHealthy()
}).then((result) => {
  //console.log(result)
  const csr = result.certificate_request
  return cfssl.sign(csr, null, {"CN": 'MY NEW CERTIFICATE', names: [{"C":"HK", "ST":"Hong Kong", "L":"Hong Kong", "O":"CompanySix"}]}, null, null, null, false)
}).then((result) => {
  const cert = result.certificate
  //console.log(result)
  return cfssl.certinfo(cert)
}).then((result) => {
  console.log(result)
}).catch((err) => {
  console.error(err)
})
