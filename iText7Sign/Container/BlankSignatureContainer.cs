using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace iText7Sign.Container
{
    class BlankSignatureContainer : IExternalSignatureContainer
    {
        private readonly PdfName filter;
        private readonly PdfName subFilter;
        private byte[] docBytesHash;
        private byte[] docDigest;
        private const String HASH_ALGORITHM = DigestAlgorithms.SHA256;
        private X509Certificate[] chain;

        public BlankSignatureContainer(PdfName filter, PdfName subFilter, X509Certificate[] chain)
        {
            this.filter = filter;
            this.subFilter = subFilter;
            this.chain = chain;
        }

        public virtual byte[] GetDocBytesHash()
        {
            return docBytesHash;
        }
        public virtual byte[] GetDocBytesDigest()
        {
            return docDigest;
        }

        public virtual byte[] Sign(Stream docBytes)
        {
            PdfPKCS7 sgn = new PdfPKCS7(null, chain, HASH_ALGORITHM, false);
            docDigest = DigestAlgorithms.Digest(docBytes, DigestAlgorithms.GetMessageDigest(HASH_ALGORITHM));
            docBytesHash = sgn.GetAuthenticatedAttributeBytes(docDigest, PdfSigner.CryptoStandard.CADES, null, null);
            using (SHA256 sha256 = SHA256.Create())
            {
                docBytesHash = sha256.ComputeHash(docBytesHash);
            }

            return new byte[0];
        }

        public virtual void ModifySigningDictionary(PdfDictionary signDic)
        {
            signDic.Put(PdfName.Filter, filter);
            signDic.Put(PdfName.SubFilter, subFilter);
        }
    }
}
