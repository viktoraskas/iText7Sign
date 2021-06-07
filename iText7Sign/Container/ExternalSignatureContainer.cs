using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Esf;
using Attribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using AttributeTable = Org.BouncyCastle.Asn1.Cms.AttributeTable;

namespace iText7Sign.Container
{
    public class ExternalSignatureContainer : IExternalSignatureContainer
    {
        private X509Certificate[] chain;
        private byte[] signature;
        X509Certificate x509Certificate;
        string keyId;
        string signingAlgorithm;
        ISignatureFactory signatureFactory;

        public ExternalSignatureContainer(X509Certificate[] chain, byte[] signature)
        {
            this.chain = chain;
            this.signature = signature;
            x509Certificate = chain[0];
        }

        public void ModifySigningDictionary(PdfDictionary signDic)
        {

        }

        public byte[] Sign(Stream data)
        {
            #region
            //PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA-256", false);
            //byte[] digest = DigestAlgorithms.Digest(data, DigestAlgorithms.GetMessageDigest("SHA-256"));
            //sgn.SetExternalDigest(signature, null, "ECDSA");
            //return sgn.GetEncodedPKCS7(digest, PdfSigner.CryptoStandard.CADES, null, null, null);
            #endregion

            MemoryStream ms = new MemoryStream();
            data.CopyTo(ms);

            var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(chain[0].GetEncoded());

            #region
            //https://stackoverflow.com/questions/10424968/add-signed-authenticated-attributes-to-cms-signature-using-bouncycastle
            
            Asn1EncodableVector signedAttributes = new Asn1EncodableVector();
            signedAttributes.Add(new Attribute(CmsAttributes.ContentType, new DerSet(new DerObjectIdentifier("1.2.840.113549.1.7.1"))));
            //signedAttributes.Add(new Attribute(CmsAttributes.MessageDigest, new DerSet(new DerOctetString(messageHash))));
            signedAttributes.Add(new Attribute(CmsAttributes.SigningTime, new DerSet(new DerUtcTime(DateTime.Now))));

            AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
            signedAttributesTable.ToAsn1EncodableVector();
            DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);

            /* Build the SignerInfo generator builder, that will build the generator... that will generate the SignerInformation... */
            //SignerInfoGeneratorBuilder signer = new SignerInfoGeneratorBuilder().;
            //signer.WithSignedAttributeGenerator

            //SignerInfoGeneratorBuilder signerInfoBuilder = new SignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().SetProvider("BC").Build());
            SignerInfoGeneratorBuilder signerInfoBuilder = new SignerInfoGeneratorBuilder();

            signerInfoBuilder.WithSignedAttributeGenerator(signedAttributeGenerator);

            CmsSignedDataGenerator generator = new CmsSignedDataGenerator();

            //JcaContentSignerBuilder contentSigner = new JcaContentSignerBuilder("SHA1withRSA");
            //contentSigner.SetProvider("BC");

            //generator.AddSignerInfoGenerator(signerInfoBuilder.Build(contentSigner.build(this.signingKey), new X509CertificateHolder(this.signingCert.getEncoded())));


            return new byte[0];
            #endregion

            #region
            ////---------------------------------- 2021 06 07 ---------------------------------------------------
            //// https://stackoverflow.com/questions/67274041/error-inserting-policy-cades-bouncy-castle-c

            //byte[] messageHash = SHA256.Create().ComputeHash(entRes);

            //byte[] certHash = SHA256.Create().ComputeHash(cert.RawData);

            //DerObjectIdentifier derobjectidentifier = new DerObjectIdentifier("1.2.840.113549.1.7.1");
            //signedAttributes.Add(new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.ContentType, new DerSet(derobjectidentifier)));

            ////1.2.840.113549.1.9.4 -> messageDigest
            //signedAttributes.Add(new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.MessageDigest, new DerSet(new DerOctetString(messageHash))));

            ////1.2.840.113549.1.9.5 -> Signing Time
            //signedAttributes.Add(new Org.BouncyCastle.Asn1.Cms.Attribute(CmsAttributes.SigningTime, new DerSet(new DerUtcTime(DateTime.Now))));

            //AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1"));

            //byte[] policyHASH = System.Text.Encoding.ASCII.GetBytes("E98BC76B0149E632CD639DE76682EE72D97F927C255C28B04A3DBCFEC632285F");

            ////sigPolicyQualifier-spuri
            //SigPolicyQualifierInfo bcSigPolicyQualifierInfo = new SigPolicyQualifierInfo(new DerObjectIdentifier("1.2.840.113549.1.9.16.5.1"), new DerIA5String("http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.der"));

            ////id-aa-ets-sigPolicyId             
            //SignaturePolicyId signaturePolicyId = new SignaturePolicyId(DerObjectIdentifier.GetInstance(new DerObjectIdentifier("2.16.76.1.7.1.1.2.3")), new OtherHashAlgAndValue(algorithmIdentifier, new DerOctetString(policyHASH)), bcSigPolicyQualifierInfo);

            ////id-aa-ets-sigPolicyId - OID 1.2.840.113549.1.9.16.2.15
            //DerObjectIdentifier identificadorPolicyID = new DerObjectIdentifier("1.2.840.113549.1.9.16.2.15");
            //signedAttributes.Add(new Org.BouncyCastle.Asn1.Cms.Attribute(identificadorPolicyID, new DerSet(signaturePolicyId)));


            //CmsSignedDataGenWithRsaCsp cms = new CmsSignedDataGenWithRsaCsp();
            //Org.BouncyCastle.Crypto.AsymmetricKeyParameter keyParameter = null;

            //dynamic rsa = (RSACryptoServiceProvider)cert.PrivateKey;
            //Org.BouncyCastle.X509.X509Certificate certCopy = DotNetUtilities.FromX509Certificate(cert);

            //cms.MyAddSigner(rsa, certCopy, keyParameter, CmsSignedDataGenerator.EncryptionRsa, CmsSignedDataGenerator.DigestSha256, attributeTable, null);

            ////-----------------------------------------------------------------------------------------------



            //if (data == null)
            //    throw new ArgumentNullException("data");
            //if (certificate == null)
            //    throw new ArgumentNullException("certificate");

            //// setup the data to sign
            //System.Security.Cryptography.Pkcs.ContentInfo content = new System.Security.Cryptography.Pkcs.ContentInfo(ms.ToArray());
            //SignedCms signedCms = new SignedCms(content, false);
            //CmsSigner signer = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate);
            //// create the signature
            //signedCms.ComputeSignature(signer);
            //return signedCms.Encode();

            //System.Security.Cryptography.Pkcs.ContentInfo contentInfo = new System.Security.Cryptography.Pkcs.ContentInfo(new Oid("1.2.840.113549.1.7.2"), signature);
            //System.Security.Cryptography.Pkcs.ContentInfo contentInfo = new System.Security.Cryptography.Pkcs.ContentInfo(ms.ToArray());

            ////Source:
            ////https://stackoverflow.com/questions/22470156/adding-external-pkcs1-byte-array-and-certificate-to-cms-container-with-java
            //// Build the items to encrypt, objects for method parameters would be obtained previously.
            //byte[] toEncrypt = ExternalSignerInfoGenerator.getCmsBytesToSign(hash,
            //            signingTime,
            //            PKCSObjectIdentifiers.data,
            //            x509Cert,
            //            timeStampToken,
            //            ocsp);
            //// The externalSignerInfoGenerator.getCmsBytesToSign is a method from a re implemention of the 
            //// SignerInf inner class from CMSSignedDataGenerator and is used to get a byte array from an 
            //// org.bouncycastle.asn1.ASN1EncodableVector. To build the vector one should add attributes to
            //// their corresponding OID's using the org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers interface,
            //// for example:
            ////Asn1EncodableVector signedAttrVector = buildSignedAttributes(hash, signingTime, contentType,x509Cert, ocspResp);
            //// This would call the buildSignedAttributes method to build the signed attributes vector
            //Asn1EncodableVector signedAttrVector = new Asn1EncodableVector();
            //// Add CMS attributes
            //signedAttrVector.Add(new Attribute(CmsAttributes.ContentType, new DerSet()));
            //signedAttrVector.Add(new Attribute(CmsAttributes.SigningTime, new DerSet(new DerUtcTime(DateTime.Now))));
            //signedAttrVector.Add(new Attribute(CmsAttributes.MessageDigest, new DerSet(new DerOctetString(hash))));

            //// Not all attributes are considered in BC's CMSAttributes interface, therefore one would have to add 
            //// an additional step:
            //signedAttrVector.Add(buildOcspResponseAttribute(ocspResp));
            //// This method would call buildOcspResponseAttribute to add the object as a PKCSObjectIdentifier
            ///*
            //protected Attribute buildOcspResponseAttribute(byte[] ocspResp) throws IOException, CMSException {
            //    return new Attribute(PKCSObjectIdentifiers.id_aa_ets_revocationRefs,
            //    new DERSet(DERUtil.readDERObject(ocspResp)));
            //}
            //*/
            //// Call sign method from provider, such as PKCS11, PKCS12, etc.
            //byte[] signature = getSignProvider().sign(toEncrypt);
            //// Now build standard org.bouncycastle.cms.SignerInfoGenerator with hash, signed data 
            //// and certificate to add to CMS, create attached or detached signature
            //// create signed envelope
            //CMSSignedData envdata = externalCMSSignedDataGenerator.generate(false);
            //byte[] enveloped = envdata.getEncoded();

































            //SignedCms signedCms = new SignedCms(SubjectIdentifierType.SubjectKeyIdentifier,contentInfo, true);
            //CmsSigner cmsSigner = new CmsSigner(SubjectIdentifierType.SubjectKeyIdentifier,certificate,);
            //cmsSigner.IncludeOption = System.Security.Cryptography.X509Certificates.X509IncludeOption.EndCertOnly;
            //cmsSigner.DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1", "SHA256");
            //cmsSigner.SignerIdentifierType = SubjectIdentifierType.IssuerAndSerialNumber;
            //cmsSigner.SignedAttributes.Add(new AsnEncodedData(new Oid("1.2.840.113549.1.7.2"), signature));
            //cmsSigner.SignedAttributes.Add()
            //signedCms.AddCertificate(certificate);
            //signedCms.ComputeSignature(cmsSigner,false);
            //byte[] myCmsMessage = signedCms.Encode();
            //return myCmsMessage;

            //ContentSigner signer = (new JcaContentSignerBuilder("SHA256withRSA") + setProvider("BC").build(pk));

            //CmsSignedDataGenerator generator = new CmsSignedDataGenerator();
            //gen.AddSignerInfoGenerator((new JcaSignerInfoGeneratorBuilder((new JcaDigestCalculatorProviderBuilder() + setProvider("BC").build())) + build(signer, ((X509Certificate)(cert)))));



            //ISigner signer = SignatureAlgorithmHelper.SHA256withECDSA.GenerateSigner();

            //CmsProcessable msg = new CmsProcessableInputStream(data);
            //CmsSignedDataGenerator gen = new CmsSignedDataGenerator();
            //SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder().WithSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator()).Build(signatureFactory, x509Certificate);

            //gen.AddSignerInfoGenerator(signerInfoGenerator);
            //X509CollectionStoreParameters collectionStoreParameters = new X509CollectionStoreParameters(new List<X509Certificate> { x509Certificate });
            //IX509Store collectionStore = X509StoreFactory.Create("CERTIFICATE/COLLECTION", collectionStoreParameters);
            //gen.AddCertificates(collectionStore);
            //CmsSignedData sigData = gen.Generate(msg, false);
            //return sigData.GetEncoded();
            #endregion
        }
    }
}
