﻿using Org.BouncyCastle.Asn1;
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

    public static void Main(String[] args)
    {
        TokenSigner tokenSigner = new TokenSigner();       

        if (args == null || args.Length < 1 || File.Exists(args[0]) == false)
        {
            Console.WriteLine("document doesnot exist");
            return;
        }

        JObject unsignedInvoice = tokenSigner.ReadJsonFromFile(args[0]);


        tokenSigner.FindCertificateFromSelector();
        //Start serialize
        String canonicalString = tokenSigner.Serialize(unsignedInvoice);

        String cades = tokenSigner.SignWithCMS(canonicalString);

        String fullSignedInvoice = tokenSigner.AddSignatureToInvoice(unsignedInvoice, cades);

        
        File.WriteAllBytes(Directory.GetCurrentDirectory() + @"\FullSignedDocument.json", System.Text.Encoding.UTF8.GetBytes(fullSignedInvoice));
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
                Where(x => x.NotAfter > DateTime.Today && DateTime.Today > x.NotBefore).
                Where(x => x.HasPrivateKey).ToArray();

            X509CertificateCollection certificates = X509Certificate2UI.SelectFromCollection(new X509Certificate2Collection(validCertificates),"Certificates","please select a certificate",X509SelectionFlag.SingleSelection);

            this.selectedCertificate = (X509Certificate2)certificates[0];
            store.Close();
        }

        private JObject ReadJsonFromFile(String FileName)
        {
            // exception 1

        String sourceDocumentJson = File.ReadAllText(FileName);

            JObject documentJson = JsonConvert.DeserializeObject<JObject>(sourceDocumentJson, new JsonSerializerSettings()
            {
                FloatFormatHandling = FloatFormatHandling.String,
                FloatParseHandling = FloatParseHandling.Decimal,
                DateFormatHandling = DateFormatHandling.IsoDateFormat,
                DateParseHandling = DateParseHandling.None
            });

        return documentJson;
            
        }

        private String AddSignatureToInvoice(JObject unsignedInvoice, String cades)
        {
            JObject signaturesObject = new JObject(
                                new JProperty("signatureType", "I"),
                                new JProperty("value", cades));

            JArray signaturesArray = new JArray();
            signaturesArray.Add(signaturesObject);
            unsignedInvoice.Add("signatures", signaturesArray);
            String fullSignedInvoice = "{\"documents\":[" + unsignedInvoice.ToString() + "]}";
        return fullSignedInvoice;
        }

        public string SignWithCMS(String serializedJson)
        {
            byte[] data = Encoding.UTF8.GetBytes(serializedJson);

            ContentInfo content = new ContentInfo(new Oid("1.2.840.113549.1.7.5"), data);
            SignedCms cms = new SignedCms(content, true);

            EssCertIDv2 bouncyCertificate = new EssCertIDv2(new Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier(new DerObjectIdentifier("1.2.840.113549.1.9.16.2.47")), this.HashBytes(this.selectedCertificate.RawData));
            SigningCertificateV2 signerCertificateV2 = new SigningCertificateV2(new EssCertIDv2[] { bouncyCertificate });
            CmsSigner signer = new CmsSigner(this.selectedCertificate);

            signer.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1");
            signer.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.UtcNow));
            signer.SignedAttributes.Add(new AsnEncodedData(new Oid("1.2.840.113549.1.9.16.2.47"), signerCertificateV2.GetEncoded()));

            // exception needs to be handled
            cms.ComputeSignature(signer, false);
            return Convert.ToBase64String(cms.Encode());
    }

    //we can give away the serializing here in C# if our serialization is good.
    public string Serialize(JObject request)
    {
        return SerializeToken(request);
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

