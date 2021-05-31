using System;

namespace iText7Sign.Models
{
    public class CertificateResponse
    {
        public string result { get; set; }
        public string cert { get; set; }
        public DateTime time { get; set; }
        public string traceId { get; set; }
    }
}
