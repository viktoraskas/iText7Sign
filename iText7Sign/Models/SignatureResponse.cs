using System;

namespace iText7Sign.Models
{
    public class SignatureResponse
    {
        public string state { get; set; }
        public string result { get; set; }
        public Signature signature { get; set; }
        public DateTime time { get; set; }
        public string traceId { get; set; }
    }
}
