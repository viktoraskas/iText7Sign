using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace iText7Sign.Container
{
    public class MyStreamCalculator : IStreamCalculator
    {
        private string signingAlgorithm;
        private MemoryStream stream = new MemoryStream();

        public MyStreamCalculator(string keyId, string signingAlgorithm)
        {
            //this.keyId = keyId;
            this.signingAlgorithm = signingAlgorithm;
        }

        public Stream Stream => stream;

        public object GetResult()
        {
            try
            {
                //using (var kmsClient = new AmazonKeyManagementServiceClient())
                {
                    //SignRequest signRequest = new SignRequest()
                    //{
                    //    SigningAlgorithm = signingAlgorithm,
                    //    KeyId = keyId,
                    //    MessageType = MessageType.RAW,
                    //    Message = new MemoryStream(stream.ToArray())
                    //};
                    //SignResponse signResponse = kmsClient.SignAsync(signRequest).Result;
                    //return new SimpleBlockResult(signResponse.Signature.ToArray());
                    return new SimpleBlockResult(new byte[0]);
                }
            }
            finally
            {
                stream = new MemoryStream();
            }
        }
    }
}
