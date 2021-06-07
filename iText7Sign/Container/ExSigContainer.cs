using ExtensionMethods;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace iText7Sign.Container
{
    class ExSigContainer : IExternalSignatureContainer
    {
        private SignaturePolicyIdentifier signaturePolicyIdentifier;
        private X509Certificate signCert;
        private ICollection<X509Certificate> signCerts;
        private ICollection<X509Certificate> certs;
        private ICollection<string> digestalgos;

        private ISigner sig;

        private byte[] digest;


        private string signName;
        private string reason;
        private string location;
        private DateTime signDate;
        private byte[] externalDigest;
        private string digestEncryptionAlgorithmOid;
        private string digestAlgorithmOid;
        private int signerversion = 1;
        private int version = 1;
        string hashAlgorithm = "SHA-256";


        private X509Certificate[] chain;
        private byte[] signature;
        X509Certificate x509Certificate;
        private byte[] externalRsaData;
        private byte[] rsaData;

        public ExSigContainer(X509Certificate[] chain, byte[] signature)
        {
            this.chain = chain;
            this.signature = signature;
            x509Certificate = chain[0];
        }

        void IExternalSignatureContainer.ModifySigningDictionary(PdfDictionary signDic)
        {

        }

        byte[] IExternalSignatureContainer.Sign(Stream data)
        {
            //PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA-256", false);
            //byte[] digest = DigestAlgorithms.Digest(data, DigestAlgorithms.GetMessageDigest("SHA-256"));
            //sgn.SetExternalDigest(signature, null, "ECDSA");
            //return sgn.GetEncodedPKCS7(digest, PdfSigner.CryptoStandard.CADES, null, null, null);

            // message digest
            if (digestAlgorithmOid == null)
            {
                throw new ArgumentException("Unknown Hash Algorithm "+ hashAlgorithm);
            }
            digestAlgorithmOid = DigestAlgorithms.GetAllowedDigest(hashAlgorithm);

            // Copy the certificates
            signCert = chain[0];
            certs = new List<X509Certificate>();
            foreach (X509Certificate element in chain)
            {
                certs.Add(element);
            }
            // initialize and add the digest algorithms.
            digestalgos = new HashSet<string>();
            digestalgos.Add(digestAlgorithmOid);

            byte[] digest = DigestAlgorithms.Digest(data, DigestAlgorithms.GetMessageDigest("SHA-256"));

            SetExternalDigest(signature, null, "ECDSA");

            return this.GetEncodedPKCS7(digest, PdfSigner.CryptoStandard.CADES, null, null, null);

        }

        private byte[] GetEncodedPKCS7(byte[] secondDigest, PdfSigner.CryptoStandard sigtype, ITSAClient tsaClient , ICollection<byte[]> ocsp, ICollection<byte[]> crlBytes)
        {
            try
            {
                if (externalDigest != null)
                {
                    digest = externalDigest;
                }
                
                // Create the set of Hash algorithms

                Asn1EncodableVector digestAlgorithms = new Asn1EncodableVector();
                foreach (Object element in digestalgos)
                {
                    Asn1EncodableVector algos = new Asn1EncodableVector();
                    algos.Add(new DerObjectIdentifier((string)element));
                    algos.Add(DerNull.Instance);
                    digestAlgorithms.Add(new DerSequence(algos));
                }
                // Create the contentInfo.
                Asn1EncodableVector v = new Asn1EncodableVector();
                v.Add(new DerObjectIdentifier(SecurityIDs.ID_PKCS7_DATA));
                //if (rsaData != null)
                //{
                //    v.Add(new DerTaggedObject(0, new DerOctetString(rsaData)));
                //}
                DerSequence contentinfo = new DerSequence(v);
                // Get all the certificates
                //
                v = new Asn1EncodableVector();
                foreach (object element in certs)
                {
                    Asn1InputStream tempstream = new Asn1InputStream(new MemoryStream(((X509Certificate)element).GetEncoded())
                        );
                    v.Add(tempstream.ReadObject());
                }
                DerSet dercertificates = new DerSet(v);
                // Create signerinfo structure.
                //
                Asn1EncodableVector signerinfo = new Asn1EncodableVector();
                // Add the signerInfo version
                //
                signerinfo.Add(new DerInteger(signerversion));
                v = new Asn1EncodableVector();
                v.Add(CertificateInfo.GetIssuer(signCert.GetTbsCertificate()));
                v.Add(new DerInteger(signCert.SerialNumber));
                signerinfo.Add(new DerSequence(v));
                // Add the digestAlgorithm
                v = new Asn1EncodableVector();
                v.Add(new DerObjectIdentifier(digestAlgorithmOid));
                v.Add(Org.BouncyCastle.Asn1.DerNull.Instance);
                signerinfo.Add(new DerSequence(v));
                // add the authenticated attribute if present
                if (secondDigest != null)
                {
                    signerinfo.Add(new DerTaggedObject(false, 0, GetAuthenticatedAttributeSet(secondDigest, ocsp, crlBytes, sigtype )));
                }
                // Add the digestEncryptionAlgorithm
                v = new Asn1EncodableVector();
                v.Add(new DerObjectIdentifier(digestEncryptionAlgorithmOid));
                v.Add(Org.BouncyCastle.Asn1.DerNull.Instance);
                signerinfo.Add(new DerSequence(v));
                // Add the digest
                signerinfo.Add(new DerOctetString(digest));
                // When requested, go get and add the timestamp. May throw an exception.
                // Added by Martin Brunecky, 07/12/2007 folowing Aiken Sam, 2006-11-15
                // Sam found Adobe expects time-stamped SHA1-1 of the encrypted digest
                if (tsaClient != null)
                {
                    byte[] tsImprint = tsaClient.GetMessageDigest().Digest(digest);
                    byte[] tsToken = tsaClient.GetTimeStampToken(tsImprint);
                    if (tsToken != null)
                    {
                        Asn1EncodableVector unauthAttributes = BuildUnauthenticatedAttributes(tsToken);
                        if (unauthAttributes != null)
                        {
                            signerinfo.Add(new DerTaggedObject(false, 1, new DerSet(unauthAttributes)));
                        }
                    }
                }
                // Finally build the body out of all the components above
                Asn1EncodableVector body = new Asn1EncodableVector();
                body.Add(new DerInteger(version));
                body.Add(new DerSet(digestAlgorithms));
                body.Add(contentinfo);
                body.Add(new DerTaggedObject(false, 0, dercertificates));
                // Only allow one signerInfo
                body.Add(new DerSet(new DerSequence(signerinfo)));
                // Now we have the body, wrap it in it's PKCS7Signed shell
                // and return it
                //
                Asn1EncodableVector whole = new Asn1EncodableVector();
                whole.Add(new DerObjectIdentifier(SecurityIDs.ID_PKCS7_SIGNED_DATA));
                whole.Add(new DerTaggedObject(0, new DerSequence(body)));
                MemoryStream bOut = new MemoryStream();
                Asn1OutputStream dout = new Asn1OutputStream(bOut);
                dout.WriteObject(new DerSequence(whole));
                dout.Dispose();
                return bOut.ToArray();
            }
            catch (Exception e)
            {
                throw new ArgumentException(e.Message,e.InnerException);
            }
        }

        private DerSet GetAuthenticatedAttributeSet(byte[] secondDigest, ICollection<byte[]> ocsp, ICollection<byte[]> crlBytes, PdfSigner.CryptoStandard sigtype)
        {
            try
            {
                Asn1EncodableVector attribute = new Asn1EncodableVector();
                Asn1EncodableVector v = new Asn1EncodableVector();
                v.Add(new DerObjectIdentifier(SecurityIDs.ID_CONTENT_TYPE));
                v.Add(new DerSet(new DerObjectIdentifier(SecurityIDs.ID_PKCS7_DATA)));
                attribute.Add(new DerSequence(v));
                v = new Asn1EncodableVector();
                v.Add(new DerObjectIdentifier(SecurityIDs.ID_MESSAGE_DIGEST));
                v.Add(new DerSet(new DerOctetString(secondDigest)));
                attribute.Add(new DerSequence(v));
                bool haveCrl = false;
                if (crlBytes != null)
                {
                    foreach (byte[] bCrl in crlBytes)
                    {
                        if (bCrl != null)
                        {
                            haveCrl = true;
                            break;
                        }
                    }
                }
                if (ocsp != null && !ocsp.IsEmpty() || haveCrl)
                {
                    v = new Asn1EncodableVector();
                    v.Add(new DerObjectIdentifier(SecurityIDs.ID_ADBE_REVOCATION));
                    Asn1EncodableVector revocationV = new Asn1EncodableVector();
                    if (haveCrl)
                    {
                        Asn1EncodableVector v2 = new Asn1EncodableVector();
                        foreach (byte[] bCrl in crlBytes)
                        {
                            if (bCrl == null)
                            {
                                continue;
                            }
                            Asn1InputStream t = new Asn1InputStream(new MemoryStream(bCrl));
                            v2.Add(t.ReadObject());
                        }
                        revocationV.Add(new DerTaggedObject(true, 0, new DerSequence(v2)));
                    }
                    if (ocsp != null && !ocsp.IsEmpty())
                    {
                        Asn1EncodableVector vo1 = new Asn1EncodableVector();
                        foreach (byte[] ocspBytes in ocsp)
                        {
                            DerOctetString doctet = new DerOctetString(ocspBytes);
                            Asn1EncodableVector v2 = new Asn1EncodableVector();
                            v2.Add(OcspObjectIdentifiers.PkixOcspBasic);
                            v2.Add(doctet);
                            DerEnumerated den = new DerEnumerated(0);
                            Asn1EncodableVector v3 = new Asn1EncodableVector();
                            v3.Add(den);
                            v3.Add(new DerTaggedObject(true, 0, new DerSequence(v2)));
                            vo1.Add(new DerSequence(v3));
                        }
                        revocationV.Add(new DerTaggedObject(true, 1, new DerSequence(vo1)));
                    }
                    v.Add(new DerSet(new DerSequence(revocationV)));
                    attribute.Add(new DerSequence(v));
                }
                if (sigtype == PdfSigner.CryptoStandard.CADES)
                {
                    v = new Asn1EncodableVector();
                    v.Add(new DerObjectIdentifier(SecurityIDs.ID_AA_SIGNING_CERTIFICATE_V2));
                    Asn1EncodableVector aaV2 = new Asn1EncodableVector();
                    AlgorithmIdentifier algoId = new AlgorithmIdentifier(new DerObjectIdentifier(digestAlgorithmOid), null);
                    aaV2.Add(algoId);
                    IDigest md = DigestUtilities.GetDigest(GetHashAlgorithm());
                    byte[] dig = md.Digest(signCert.GetEncoded());
                    aaV2.Add(new DerOctetString(dig));
                    v.Add(new DerSet(new DerSequence(new DerSequence(new DerSequence(aaV2)))));
                    attribute.Add(new DerSequence(v));
                }
                if (signaturePolicyIdentifier != null)
                {
                    attribute.Add(new Org.BouncyCastle.Asn1.Cms.Attribute(Org.BouncyCastle.Asn1.Pkcs.PkcsObjectIdentifiers.IdAAEtsSigPolicyID
                        , new DerSet(signaturePolicyIdentifier)));
                }
                return new DerSet(attribute);
            }
            catch (Exception e)
            {
                throw new ArgumentException(e.Message, e.InnerException);
            }
        }

        private void SetExternalDigest(byte[] digest, byte[] rsaData, string digestEncryptionAlgorithm)
        {
            externalDigest = digest;
            externalRsaData = rsaData;
            if (digestEncryptionAlgorithm != null)
            {
                if (digestEncryptionAlgorithm.Equals("ECDSA"))
                {
                    //this.digestEncryptionAlgorithmOid = SecurityIDs.ID_ECDSA;
                    this.digestEncryptionAlgorithmOid = "1.2.840.10045.4.3.2";
                }
                else
                {
                    throw new ArgumentException("Unknown digest encryption algorith " + digestEncryptionAlgorithm, nameof(digestEncryptionAlgorithm));
                }
            }
            else throw new ArgumentException("Not defined digest encryption algorith");
        }

        private Asn1EncodableVector BuildUnauthenticatedAttributes(byte[] timeStampToken)
        {
            if (timeStampToken == null)
            {
                return null;
            }
            // @todo: move this together with the rest of the defintions
            String ID_TIME_STAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";
            // RFC 3161 id-aa-timeStampToken
            Asn1InputStream tempstream = new Asn1InputStream(new MemoryStream(timeStampToken));
            Asn1EncodableVector unauthAttributes = new Asn1EncodableVector();
            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(new DerObjectIdentifier(ID_TIME_STAMP_TOKEN));
            // id-aa-timeStampToken
            Asn1Sequence seq = (Asn1Sequence)tempstream.ReadObject();
            v.Add(new DerSet(seq));
            unauthAttributes.Add(new DerSequence(v));
            return unauthAttributes;
        }

        private string GetHashAlgorithm()
        {
            return DigestAlgorithms.GetDigest(digestAlgorithmOid);
        }
    }
}
