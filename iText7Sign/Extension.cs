using System;
using System.Collections.Generic;
using ExtensionMethods;
using Org.BouncyCastle.Crypto;

namespace ExtensionMethods
{
    public static class Extension
    {
        public static bool IsEmpty<T>(this ICollection<T> collection)
        {
            return collection.Count == 0;
        }

        public static void Update(this ISigner signer, byte[] data)
        {
            signer.BlockUpdate(data, 0, data.Length);
        }

        public static void Update(this ISigner signer, byte[] data, int offset, int count)
        {
            signer.BlockUpdate(data, offset, count);
        }
        public static void Update(this IDigest dgst, byte[] input)
        {
            dgst.Update(input, 0, input.Length);
        }
        public static void Update(this IDigest dgst, byte[] input, int offset, int len)
        {
            dgst.BlockUpdate(input, offset, len);
        }
        public static byte[] Digest(this IDigest dgst)
        {
            byte[] output = new byte[dgst.GetDigestSize()];
            dgst.DoFinal(output, 0);
            return output;
        }
        public static byte[] Digest(this IDigest dgst, byte[] input)
        {
            dgst.Update(input);
            return dgst.Digest();
        }

    }
}
