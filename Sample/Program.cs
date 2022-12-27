using kalkanNet;

var cert_path = "";
var cert_pass = "";
var xml = "<xml></xml>";
var client = new KalkanClient(new KalkanOptions());
        
client.LoadKeyStore(cert_pass, cert_path, KCStoreType.KCStoreTypePKCS12, "");
var signXml = client.SignXML(xml, "", "", "", "");

Console.WriteLine(signXml);