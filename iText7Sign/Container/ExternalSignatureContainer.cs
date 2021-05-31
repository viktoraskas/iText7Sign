using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace iText7Sign.Container
{
    public class ExternalSignatureContainer : IExternalSignatureContainer
    {
        private X509Certificate[] chain;
        private byte[] signature;
        private string hashAlgorithm;

        public ExternalSignatureContainer(X509Certificate[] chain, byte[] signature, string hashAlgorithm)
        {
            this.chain = chain;
            this.signature = signature;
            this.hashAlgorithm = hashAlgorithm;
        }

        public void ModifySigningDictionary(PdfDictionary signDic)
        {

        }

        public byte[] Sign(Stream data)
        {

            string hashAlgorithm = "SHA256";
            PdfPKCS7 sgn = new PdfPKCS7(null, chain, hashAlgorithm, false);
            byte[] digest = DigestAlgorithms.Digest(data, DigestAlgorithms.GetMessageDigest(hashAlgorithm));
            sgn.SetExternalDigest(signature, null, "ECDSA");
            return sgn.GetEncodedPKCS7(digest, PdfSigner.CryptoStandard.CADES, null, null, null);
        }
    }
}
