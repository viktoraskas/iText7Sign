namespace iText7Sign.Models
{
    public class CertificateRequest
    {
        public string relyingPartyUUID { get; set; }
        public string relyingPartyName { get; set; }
        public string phoneNumber { get; set; }
        public string nationalIdentityNumber { get; set; }
    }
}
