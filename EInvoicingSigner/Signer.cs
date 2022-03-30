using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;

public class TokenSigner
{
    private X509Certificate2 selectedCertificate;
    private List<String> knownIssuers = new List<String> { "MCDR", "Investors CA", "Egypt Trust" };

    public static void Main(String[] args)
    {
        TokenSigner tokenSigner = new TokenSigner();
        List<Invoice> invoices = new List<Invoice>();
        List<String> consoleOutput = new List<String>();

        if (args.Length < 1 || File.Exists(args[0]) == false)
        {
            Console.Write("null_or_wrong_argument");
            Environment.Exit(0);
        }


        foreach (var invoiceName in args)
        {
            JObject unsignedInvoice = null;
            try
            {
                unsignedInvoice = tokenSigner.ReadJsonFromFile(invoiceName);
            }
            catch (Exception)
            {
                Console.Write("Invoice Parsing Error");
                Environment.Exit(0);
            }
            invoices.Add(new Invoice(unsignedInvoice, invoiceName));
        }

        tokenSigner.FindCertificateFromSelector();

        foreach (var invoice in invoices)
        {
            String canonicalString = invoice.getCanonicalString();
            String cades = String.Empty;
            try
            {
                cades = tokenSigner.SignWithCMS(canonicalString);                
            }
            catch (Exception)
            {
                invoice.setStatus("Invalid Certificate!");
                continue;
            }

            invoice.writeInvoiceAfterSigning(cades);
            consoleOutput.Add(invoice.getStatus());
        }

        Console.Write(String.Join(',', consoleOutput));
        Environment.Exit(0);
    }

    public JObject ReadJsonFromFile(String FileName)
    {
        String sourceDocumentJson = File.ReadAllText(FileName);

        return JsonConvert.DeserializeObject<JObject>(sourceDocumentJson, new JsonSerializerSettings()
        {
            FloatFormatHandling = FloatFormatHandling.String,
            FloatParseHandling = FloatParseHandling.Decimal,
            DateFormatHandling = DateFormatHandling.IsoDateFormat,
            DateParseHandling = DateParseHandling.None
        });
    }

    private void FindCertificateFromSelector()
    {
        X509Store store;
        try
        {
            store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly & OpenFlags.OpenExistingOnly);
        }
        catch (Exception)
        {

            Console.Write("There is a problem opening the Certificates Store.");
            Environment.Exit(0);
            return;
        }

        X509Certificate2[]? validCertificates = store.Certificates.Where(x => this.knownIssuers.Any(s => Regex.IsMatch(x.Issuer.ToString(), s))).
            Where(x => x.HasPrivateKey).ToArray();
        //Where(x => x.NotAfter > DateTime.Today && DateTime.Today > x.NotBefore).


        X509CertificateCollection certificates = X509Certificate2UI.SelectFromCollection(new X509Certificate2Collection(validCertificates), "Certificates", "please select a certificate", X509SelectionFlag.SingleSelection);

        try
        {
            this.selectedCertificate = (X509Certificate2)certificates[0];
        }
        catch (Exception)
        {
            Console.Write("No Certificate Selected.");
            Environment.Exit(0);
        }
        store.Close();
    }

    public String SignWithCMS(String canonicalString)
    {
        byte[] data = Encoding.UTF8.GetBytes(canonicalString);

        ContentInfo content = new ContentInfo(new Oid("1.2.840.113549.1.7.5"), data);
        SignedCms cms = new SignedCms(content, true);

        EssCertIDv2 bouncyCertificate = new EssCertIDv2(new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.9.16.2.47")), this.HashBytes(this.selectedCertificate.RawData));
        SigningCertificateV2 signerCertificateV2 = new SigningCertificateV2(new EssCertIDv2[] { bouncyCertificate });

        CmsSigner signer = new CmsSigner(this.selectedCertificate)
        {
            DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1")
        };

        signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
        signer.SignedAttributes.Add(new AsnEncodedData(new Oid("1.2.840.113549.1.9.16.2.47"), signerCertificateV2.GetEncoded()));


        try
        {
            cms.ComputeSignature(signer, false);
        }
        catch (Exception)
        {
            Console.Write("Incorrect PIN or The Certificate has no PIN");
            Environment.Exit(0);
        }
        return Convert.ToBase64String(cms.Encode());
    }
    private byte[] HashBytes(byte[] input)
    {
        using (SHA256 sha = SHA256.Create())
        {
            var output = sha.ComputeHash(input);
            return output;
        }
    }
}

public class Invoice
{
    private JObject unsignedInvoice;
    private String filePath = String.Empty;
    private String canonicalString = String.Empty;
    private String cades = String.Empty;
    private String fullSignedInvoice = String.Empty;
    private String identifierTimestamp = DateTimeOffset.Now.ToUnixTimeMilliseconds().ToString();
    private String invoiceStatus = String.Empty;
    private String signatureType = "I";

    public Invoice(JObject unsingnedInvoice, String filePath)
    {
        this.unsignedInvoice = unsingnedInvoice;
        this.filePath = filePath;

        try
        {
            this.canonicalString = SerializeToken(this.unsignedInvoice);
        }
        catch (Exception)
        {
            Console.Write("Error Upon Serializing the invoice.");
            Environment.Exit(0);
        }
    }

    public String getCanonicalString()
    {
        return this.canonicalString;
    }
    public void setStatus(String status)
    {
        this.invoiceStatus = status;
    }

    public String getStatus()
    {
        return this.invoiceStatus;
    }
    public void writeInvoiceAfterSigning(String cades)
    {
        this.cades = cades;

        try
        {
            this.AddSignatureToInvoice();
        }
        catch (Exception)
        {
            this.invoiceStatus = "Error on Embedding The Signature To the Invoice.";
        }

        try
        {
            this.WriteSignedInvoiceToFile();
        }
        catch (Exception)
        {
            this.invoiceStatus = "Couldn't Write the Signed Invoice to a new file";
        }
    }

    private string SerializeToken(JToken request)
    {
        string serialized = "";
        if (request.Parent is null)
        {
            SerializeToken(request.First);
        }
        else
        {
            if (request.Type == JTokenType.Property)
            {
                string name = ((JProperty)request).Name.ToUpper();
                serialized += "\"" + name + "\"";
                foreach (var property in request)
                {
                    if (property.Type == JTokenType.Object)
                    {
                        serialized += SerializeToken(property);
                    }
                    if (property.Type == JTokenType.Boolean || property.Type == JTokenType.Integer || property.Type == JTokenType.Float || property.Type == JTokenType.Date)
                    {
                        serialized += "\"" + property.Value<string>() + "\"";
                    }
                    if (property.Type == JTokenType.String)
                    {
                        serialized += JsonConvert.ToString(property.Value<string>());
                    }
                    if (property.Type == JTokenType.Array)
                    {
                        foreach (var item in property.Children())
                        {
                            serialized += "\"" + ((JProperty)request).Name.ToUpper() + "\"";
                            serialized += SerializeToken(item);
                        }
                    }
                }
            }
            if (request.Type == JTokenType.String)
            {
                serialized += JsonConvert.ToString(request.Value<string>());
            }
        }
        if (request.Type == JTokenType.Object)
        {
            foreach (var property in request.Children())
            {

                if (property.Type == JTokenType.Object || property.Type == JTokenType.Property)
                {
                    serialized += SerializeToken(property);
                }
            }
        }

        return serialized;
    }

    private void AddSignatureToInvoice()
    {
        JObject signaturesObject = new JObject(
                            new JProperty("signatureType", this.signatureType),
                            new JProperty("value", this.cades));

        JArray signaturesArray = new JArray();
        signaturesArray.Add(signaturesObject);
        unsignedInvoice.Add("signatures", signaturesArray);
        this.fullSignedInvoice = "{\"documents\":[" + this.unsignedInvoice.ToString() + "]}";
    }

    private void WriteSignedInvoiceToFile()
    {
        String path = Path.GetDirectoryName(this.filePath);

        if (String.IsNullOrEmpty(path))
        {
            path = Directory.GetCurrentDirectory();
        }

        String signedInvoiceName = $"SignedInvoice_{this.identifierTimestamp}.json";
        File.WriteAllBytes(path + '\\' + signedInvoiceName, System.Text.Encoding.UTF8.GetBytes(this.fullSignedInvoice));
        this.invoiceStatus = signedInvoiceName;
    }
}