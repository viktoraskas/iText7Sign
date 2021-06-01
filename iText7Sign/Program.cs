using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using iText7Sign.Container;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;

namespace iText7Sign
{
    class Program
    {
        static void Main(string[] args)
        {
            string fieldName = "Sign";
            string src_file = @"c:\pdf\hello_world.pdf";
            string tmp_file = @"c:\pdf\hello_world_tmp.pdf";
            string dst_file = @"c:\pdf\hello_world_signed.pdf";
            string ca = @"c:\pdf\ca.pem";

            string ca_b64 = "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";

            //SSL certificate CN=mid.sk.ee
            string ca1_b64 = "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";

            string crt_b64 = "";

            ClientMID mID = new ClientMID(null, null, null, null, null);

            crt_b64 = mID.GetCertificate();
            X509Certificate[] chain = CreateChainFromBase64(crt_b64, ca_b64);

            byte[] notSignedDigest ;
            byte[] signedDigest;

            //create empty signature
            PdfReader reader = new PdfReader(src_file);

            byte[] fileArray = null;
            using (MemoryStream os = new MemoryStream())
            {
                PdfSigner stamper = new PdfSigner(reader, os, new StampingProperties());
                stamper.SetCertificationLevel(PdfSigner.NOT_CERTIFIED);
                PdfSignatureAppearance appearance = stamper.GetSignatureAppearance();
                appearance.SetPageRect(new Rectangle(10, 800, 80, 40));
                appearance.SetReason("Who I am");
                appearance.SetReasonCaption("Reason: ");
                appearance.SetSignatureCreator("SV");
                appearance.SetLocationCaption("C: ");
                appearance.SetLocation("T");
                appearance.SetCertificate(chain[0]);
                stamper.SetFieldName(fieldName);

                var external = new BlankSignatureContainer(PdfName.Adobe_PPKLite, PdfName.ETSI_CAdES_DETACHED, chain);
                stamper.SignExternalContainer(external, 8192);
                notSignedDigest = external.GetDocBytesHash();
                fileArray = os.ToArray();
            }

            var res = mID.GetSignature(Convert.ToBase64String(notSignedDigest),15);
            signedDigest = Convert.FromBase64String(res);


            File.WriteAllBytes(tmp_file, fileArray);

            using (var ms = new MemoryStream())
            using (var reader1 = new PdfReader(tmp_file))
            {
                var final = new ExternalSignatureContainer(chain, signedDigest, "ECDSA");
                PdfSigner signer = new PdfSigner(reader1, ms, new StampingProperties());
                PdfSigner.SignDeferred(signer.GetDocument(), fieldName, ms, final);
                File.WriteAllBytes(dst_file, ms.ToArray());
            }

            Console.WriteLine("Done!");
        }

        public static X509Certificate[] CreateChainFromBase64(string crt, string ca)
        {

            X509Certificate[] chain = new X509Certificate[2];
            X509CertificateParser parser = new X509CertificateParser();
            chain[0] = new X509Certificate(parser.ReadCertificate(Convert.FromBase64String(crt)).CertificateStructure);
            chain[1] = new X509Certificate(parser.ReadCertificate(Convert.FromBase64String(ca)).CertificateStructure);
            return chain;
        }
    }
}
