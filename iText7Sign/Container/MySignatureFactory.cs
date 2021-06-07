using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace iText7Sign.Container
{
    public class MySignatureFactory : ISignatureFactory
    {
        private string keyId;
        private string signingAlgorithm;
        private AlgorithmIdentifier signatureAlgorithm;

        public MySignatureFactory(string keyId, string signingAlgorithm)
        {
            this.keyId = keyId;
            this.signingAlgorithm = signingAlgorithm;
            string signatureAlgorithmName = signingAlgorithmNameBySpec[signingAlgorithm];
            if (signatureAlgorithmName == null)
                throw new ArgumentException("Unknown signature algorithm " + signingAlgorithm, nameof(signingAlgorithm));

            // Special treatment because of issue https://github.com/bcgit/bc-csharp/issues/250
            switch (signatureAlgorithmName.ToUpperInvariant())
            {
                case "SHA256WITHECDSA":
                    this.signatureAlgorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha256);
                    break;
                case "SHA512WITHECDSA":
                    this.signatureAlgorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha512);
                    break;
                default:
                    this.signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().Find(signatureAlgorithmName);
                    break;
            }
        }

        public object AlgorithmDetails => signatureAlgorithm;

        public IStreamCalculator CreateCalculator()
        {
            return new MyStreamCalculator(keyId, signingAlgorithm);
        }

        static Dictionary<string,string> signingAlgorithmNameBySpec = new Dictionary<string, string>()
    {
        { "ECDSA_SHA_256", "SHA256withECDSA" },
        { "ECDSA_SHA_384", "SHA384withECDSA" },
        { "ECDSA_SHA_512", "SHA512withECDSA" },
        { "RSASSA_PKCS1_V1_5_SHA_256", "SHA256withRSA" },
        { "RSASSA_PKCS1_V1_5_SHA_384", "SHA384withRSA" },
        { "RSASSA_PKCS1_V1_5_SHA_512", "SHA512withRSA" },
        { "RSASSA_PSS_SHA_256", "SHA256withRSAandMGF1"},
        { "RSASSA_PSS_SHA_384", "SHA384withRSAandMGF1"},
        { "RSASSA_PSS_SHA_512", "SHA512withRSAandMGF1"}
    };
    }
}
