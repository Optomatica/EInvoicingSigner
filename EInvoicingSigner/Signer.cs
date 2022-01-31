using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ess;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Text;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

public class TokenSigner
    {
        private X509Certificate2 selectedCertificate;
        private JObject unsignedInvoice;
        private String canonicalString;
        private String cades;
        private String fullSignedInvoice;
        private List<String> knownIssuers = new List<String> { "MCDR", "Investors CA" };
        private String signatureType = "I";
        private String identifierTimestamp = DateTimeOffset.Now.ToUnixTimeSeconds().ToString();

    public static void Main(String[] args)
        {
            TokenSigner tokenSigner = new TokenSigner();

            if (args.Length < 1 || File.Exists(args[0]) == false)
            {
                Console.WriteLine("null_or_wrong_argument");
                return;
            }
       
            tokenSigner.ReadJsonFromFile(args[0]);

            tokenSigner.FindCertificateFromSelector();

            try
            {
                tokenSigner.Serialize();
            }
            catch (Exception)
            {
                Console.WriteLine("Error Upon Serializing the invoice.");
                return;
            }

            try
            {
                tokenSigner.SignWithCMS();
            }
            catch (Exception)
            {
                Console.WriteLine("Invalid Certificate!");
                return;
            }

            try
            {
                tokenSigner.AddSignatureToInvoice();
            }
            catch (Exception)
            {
                Console.WriteLine("Error on Embedding The Signature To the Invoice.");
;                return;
            }

            try
            {
                tokenSigner.WriteSignedInvoiceToFile();
            }
            catch (Exception)
            {
                Console.WriteLine("Couldn't Write the Signed Invoice to a new file");
                return;
            }
        }

        private void ReadJsonFromFile(String FileName)
        {
            String sourceDocumentJson = File.ReadAllText(FileName);

            try
            {
                this.unsignedInvoice = JsonConvert.DeserializeObject<JObject>(sourceDocumentJson, new JsonSerializerSettings()
                {
                    FloatFormatHandling = FloatFormatHandling.String,
                    FloatParseHandling = FloatParseHandling.Decimal,
                    DateFormatHandling = DateFormatHandling.IsoDateFormat,
                    DateParseHandling = DateParseHandling.None
                });
            }
            catch (Exception)
            {
                Console.WriteLine("Invoice Parsing Error");
                return;
            }
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

                Console.WriteLine("There is a problem opening the Certificates Store.");
                return;
            }
            
            X509Certificate2[]? validCertificates = store.Certificates.Where(x => this.knownIssuers.Any(s => Regex.IsMatch(x.Issuer.ToString(), s))).
                Where(x => x.HasPrivateKey).ToArray();
                //Where(x => x.NotAfter > DateTime.Today && DateTime.Today > x.NotBefore).
                

            X509CertificateCollection certificates = X509Certificate2UI.SelectFromCollection(new X509Certificate2Collection(validCertificates),"Certificates","please select a certificate",X509SelectionFlag.SingleSelection);

            try
            {
                this.selectedCertificate = (X509Certificate2)certificates[0];
            }
            catch (Exception)
            {
                Console.WriteLine("No Certificate Selected.");
                return;
            }
            store.Close();
        }

        public void Serialize()
        {
            this.canonicalString = SerializeToken(this.unsignedInvoice);
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
                        if(property.Type == JTokenType.String)
                        {
                            serialized +=  JsonConvert.ToString(property.Value<string>()) ;
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
        
        private byte[] HashBytes(byte[] input)
        {
            using (SHA256 sha = SHA256.Create())
            {
                var output = sha.ComputeHash(input);
                return output;
            }
        }

        public void SignWithCMS()
        {
            byte[] data = Encoding.UTF8.GetBytes(this.canonicalString);

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
                Console.WriteLine("Incorrect PIN or The Certificate has no PIN");
                return;
            }
            this.cades = Convert.ToBase64String(cms.Encode());
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
            String signedInvoiceName = $"SignedInvoice_{this.identifierTimestamp}.json";
            File.WriteAllBytes(Directory.GetCurrentDirectory() +'\\'+ signedInvoiceName, System.Text.Encoding.UTF8.GetBytes(this.fullSignedInvoice));
            Console.WriteLine(signedInvoiceName);
        }
}

