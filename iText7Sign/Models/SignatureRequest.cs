
namespace iText7Sign.Models
{
    public class SignatureRequest
    {
        public string relyingPartyUUID { get; set; }
        public string relyingPartyName { get; set; }
        public string phoneNumber { get; set; }
        public string nationalIdentityNumber { get; set; }
        public string hash { get; set; }
        public string hashType { get; set; }
        public string language { get; set; }
        public string displayText { get; set; }
        public string displayTextFormat { get; set; }
    }
}
