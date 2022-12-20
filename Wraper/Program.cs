using kalkanNet;

public static class Program
{
    public  static void Main()
    {
        var cert_path = "";
        var cert_pass = "";
        var xml = "<xml></xml>";
        var client = new KalkanClient(new Options(), new HttpClient());
        
        client.LoadKeyStore(cert_pass, cert_path, KCStoreType.KCStoreTypePKCS12, "");
        var signXml = client.SignXML(xml, "", "", "", "");

        Console.WriteLine(signXml);
    }

}