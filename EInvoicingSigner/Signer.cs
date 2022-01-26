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

        public static void Main(String[] args)
        {
            TokenSigner tokenSigner = new TokenSigner();

            if (args == null || args.Length < 1 || File.Exists(args[0]) == false)
            {
                Console.WriteLine("document doesnot exist");
                return;
                //throw new ArgumentException("Errorneous Argument");
            }

            tokenSigner.ReadJsonFromFile(args[0]);

            tokenSigner.FindCertificateFromSelector();
        
            tokenSigner.Serialize();

            tokenSigner.SignWithCMS();

            tokenSigner.AddSignatureToInvoice();
            tokenSigner.WriteSignedInvoiceToFile();
        }

        private byte[] HashBytes(byte[] input)
        {
            using (SHA256 sha = SHA256.Create())
            {
                var output = sha.ComputeHash(input);
                return output;
            }
        }

        private void FindCertificateFromSelector()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            List<String> knownIssures = new List<String> { "MCDR", "Investors CA" };

            store.Open(OpenFlags.ReadOnly & OpenFlags.OpenExistingOnly);
            X509Certificate2[]? validCertificates = store.Certificates.Where(x => knownIssures.Any(s => Regex.IsMatch(x.Issuer.ToString(), s))).
                Where(x => x.HasPrivateKey).ToArray();
                //Where(x => x.NotAfter > DateTime.Today && DateTime.Today > x.NotBefore).
                

            X509CertificateCollection certificates = X509Certificate2UI.SelectFromCollection(new X509Certificate2Collection(validCertificates),"Certificates","please select a certificate",X509SelectionFlag.SingleSelection);

            this.selectedCertificate = (X509Certificate2)certificates[0];
            store.Close();
        }

        private void ReadJsonFromFile(String FileName)
        {
            // exception 1

        /*catch (Exception ex)
        {
            if (ex is FormatException || ex is OverflowException)
            {
                WebId = Guid.Empty;
                return;
            }

            throw;

        }*/
            String sourceDocumentJson = File.ReadAllText(FileName);

            this.unsignedInvoice = JsonConvert.DeserializeObject<JObject>(sourceDocumentJson, new JsonSerializerSettings()
                {
                    FloatFormatHandling = FloatFormatHandling.String,
                    FloatParseHandling = FloatParseHandling.Decimal,
                    DateFormatHandling = DateFormatHandling.IsoDateFormat,
                    DateParseHandling = DateParseHandling.None
                });
        }

        private void WriteSignedInvoiceToFile() 
        {
            String signedInvoiceName = "SignedInvoice.json";
            File.WriteAllBytes(Directory.GetCurrentDirectory() +'\\'+ signedInvoiceName, System.Text.Encoding.UTF8.GetBytes(this.fullSignedInvoice));
        }

        private void AddSignatureToInvoice()
        {
            JObject signaturesObject = new JObject(
                                new JProperty("signatureType", "I"),
                                new JProperty("value", this.cades));

            JArray signaturesArray = new JArray();
            signaturesArray.Add(signaturesObject);
            unsignedInvoice.Add("signatures", signaturesArray);
            this.fullSignedInvoice = "{\"documents\":[" + this.unsignedInvoice.ToString() + "]}";            
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

            // exception needs to be handled
            cms.ComputeSignature(signer, false);
            this.cades = Convert.ToBase64String(cms.Encode());
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
}

