using iText7Sign.Models;
using Newtonsoft.Json;
using Org.BouncyCastle.X509;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace iText7Sign
{
    class ClientMID
    {
        public string baseUrl { get; private set; } = @"https://tsp.demo.sk.ee/mid-api";
        public string phoneNumber { get; private set; } = "+37200000766";
        public string nationalIdentityNumber { get; private set; } = "60001019906";
        public string relyingPartyUUID { get; private set; } = "00000000-0000-0000-0000-000000000000";
        public string relyingPartyName { get; private set; } = "DEMO";

        RestClient client;


        public ClientMID(string baseUrl, string relyingPartyUUID, string relyingPartyName, string phoneNumber, string nationalIdentityNumber)
        {
            if (baseUrl != null) this.baseUrl = baseUrl;
            if (relyingPartyUUID != null) this.relyingPartyUUID = relyingPartyUUID;
            if (relyingPartyName != null) this.relyingPartyName = relyingPartyName;
            if (phoneNumber != null) this.phoneNumber = phoneNumber;
            if (nationalIdentityNumber != null) this.nationalIdentityNumber = nationalIdentityNumber;
            if (client == null) client = new RestClient(this.baseUrl);
        }

        public string GetCertificate()
        {
            string method = "/certificate";
            CertificateRequest certificateRequest = new CertificateRequest();
            certificateRequest.relyingPartyUUID = relyingPartyUUID;
            certificateRequest.relyingPartyName = relyingPartyName;
            certificateRequest.phoneNumber = phoneNumber;
            certificateRequest.nationalIdentityNumber = nationalIdentityNumber;

            RestRequest request = new RestRequest(method, Method.POST);
            request.AddHeader("Accept", "application/json");
            request.Parameters.Clear();
            request.AddJsonBody(JsonConvert.SerializeObject(certificateRequest));
            //return JsonConvert.SerializeObject(certificateRequest);
            var result = client.Execute(request);
            string returnValue = null;
            if (result.StatusCode != HttpStatusCode.OK) returnValue = result.ErrorMessage;

            if (result.StatusCode == HttpStatusCode.OK)
            {
                returnValue = JsonConvert.DeserializeObject<CertificateResponse>(result.Content).cert; // dar reikia pasitikrinti ar Content yra Json
            }

            return returnValue;

        }

        public string GetSignature(string pdfHash, int timeSpan)
        {
            string state = "RUNNING";
            string returnValue = null;
            string sessionID = null;
            if (pdfHash == null || pdfHash == "")
            {
                throw new InvalidOperationException("Hash is null");
            }
            string method = "/signature";
            SignatureRequest signatureRequest = new SignatureRequest()
            {
                relyingPartyName = relyingPartyName,
                relyingPartyUUID = relyingPartyUUID,
                phoneNumber = phoneNumber,
                nationalIdentityNumber = nationalIdentityNumber,
                hash = pdfHash,
                hashType = "SHA256",
                language = "ENG",
                displayText = "This is display text",
                displayTextFormat = "GSM-7"
            };

            RestRequest request = new RestRequest(method, Method.POST);
            request.AddHeader("Accept", "application/json");
            request.Parameters.Clear();
            request.AddJsonBody(JsonConvert.SerializeObject(signatureRequest));
            var result = client.Execute(request);

            if (result.StatusCode != HttpStatusCode.OK)
            {
                return result.ErrorMessage;
            }

            if (result.StatusCode == HttpStatusCode.OK) sessionID = JsonConvert.DeserializeObject<SessionIdResponse>(result.Content).sessionID;

            method = method + "/session/" + sessionID;
            //return method;
            request = new RestRequest(method, Method.GET);
            request.AddHeader("Accept", "application/json");
            request.Parameters.Clear();
            result = client.Execute(request);

            if (result.StatusCode != HttpStatusCode.OK)

            {
                returnValue = "";
                state = "COMPLETE";
            }

            int i = 1000;
            int t = timeSpan;

            while (state == "RUNNING")
            {
                Thread.Sleep(t);
                result = client.Execute(request);
                if (result.StatusCode == HttpStatusCode.OK)
                {
                    var resp = JsonConvert.DeserializeObject<SignatureResponse>(result.Content);

                    if (resp.state == "COMPLETE")
                    {
                        if (resp.result == "OK")
                        {
                            returnValue = resp.signature.value;
                            state = "COMPLETE";
                        }
                        if (resp.result == "USER_CANCELLED")
                        {
                            returnValue = "";
                            state = "COMPLETE";
                        }
                    }
                    //returnValue = JsonConvert.DeserializeObject<SignatureResponse>(result.Content).signature.value;
                }
                t = t - i;
            }

            //return sessionID;                
            return returnValue;
        }

        public X509Certificate[] GetChain(string crt, string ca)
        {
            X509Certificate[] chainy = new X509Certificate[2];
            X509CertificateParser parser = new X509CertificateParser();
            chainy[0] = new X509Certificate(parser.ReadCertificate(Encoding.UTF8.GetBytes(crt)).CertificateStructure);
            chainy[1] = new X509Certificate(parser.ReadCertificate(Encoding.UTF8.GetBytes(ca)).CertificateStructure);
            return chainy;
        }
    }
}
