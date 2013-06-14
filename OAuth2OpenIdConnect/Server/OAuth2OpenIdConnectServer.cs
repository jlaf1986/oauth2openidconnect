using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using OAuth2OpenIdConnect.Models;
using System.Web;
using System.Net;
using Microsoft.IdentityModel.Tokens.JWT;
using System.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Security.Claims;
using System.Security.Cryptography;

namespace OAuth2OpenIdConnect.Server
{
    public static class OAuth2OpenIdConnectServer
    {
       

       // string _issuer { get; set; }

        /// <summary>
        /// Checks pre-conditions for OpenID Connect Protocol
        /// </summary>
        /// <param name="authorizationRequest"></param>
        /// <returns></returns>
        public static void ValidateAuthRequest(HttpRequestBase request)
        {

            string responseType = request.QueryString["response_type"];
            string clientId = request.QueryString["client_id"];
            string redirectUri = request.QueryString["redirect_uri"];
            string scope = request.QueryString["scope"];
            string state = request.QueryString["state"];

            if (String.IsNullOrEmpty(responseType) || string.IsNullOrEmpty(scope) || String.IsNullOrEmpty(clientId) || String.IsNullOrEmpty(state) || String.IsNullOrEmpty(redirectUri))
            {
                throw new HttpException((int)HttpStatusCode.BadRequest, "Request does not comply with OpenId Connect protocol");

            }
            else
            {
                if (responseType != "code" || !scope.Contains(OpenIdConnectScopes.OpenId) )
                {
                    throw new HttpException((int)HttpStatusCode.BadRequest, "Request does not comply with OpenId Connect protocol");
                }
            }

        }

        

     
         
        /// <summary>
        /// Validates if the Token Request Format is valid according to OpenID Connect Protocol v1 draft 26
        /// </summary>
        /// <param name="tokenRequest"></param>
        /// <returns></returns>
        public static void ValidateTokenRequest(HttpRequestBase request)
        {

            if (request == null)
            {
                throw new ApplicationException("HttpRequest is null");
            }

            if (request.ContentType != "application/x-www-form-urlencoded")
            {
                throw new HttpException((int)HttpStatusCode.BadRequest, "Content Type does not comply with OpenId Connect protocol");
            }

            if (OAuth2OpenIdConnectServer.IsAuthorizationValid(request))
            {
                if (IsBasicAuthorization(request))
                {
                  
                    string code = request.Form["code"];
                    string grantType = request.Form["grant_type"];
                    string redirectUri = request.Form["redirect_uri"];

                    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(grantType) || grantType != "authorization_code" || string.IsNullOrEmpty(redirectUri))
                    {
                        throw new HttpException((int)HttpStatusCode.BadRequest, "Request does not comply with OpenID Connect Protocol");
                    }
                    else
                    {
                        return;
                    }

                }
                 
            }
            else
            {
                throw new HttpException((int) HttpStatusCode.BadRequest, "Request does not comply with OpenID Connect Protocol");
              
            }
             
        }


        /// <summary>
        /// Returns the OpenID token already serialized to be sent to the client
        /// </summary>
        /// <param name="tokenRequest"></param>
        /// <returns></returns>
        public static OpenIdConnectTokenRequestResponse GenerateOpenIdConnectToken(string issuer, string audience, string subject, string code, string scopes, int expiresIn=0)
        {


            if (string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(audience) || string.IsNullOrEmpty(subject) || string.IsNullOrEmpty(code) || string.IsNullOrEmpty(scopes) || expiresIn<0)
            {
                throw new ApplicationException("The parameters provided are not valid");
            }
             
            DateTime issuedAt = DateTime.UtcNow;
            DateTime expires = DateTime.UtcNow.AddMinutes(2);

            JWTSecurityTokenHandler jwtHandler = new JWTSecurityTokenHandler();

            // Create a simple JWT claim set
            IList<Claim> claims = new List<Claim>() { 
                                            new Claim("sub", subject),
                                            new Claim("iat", ToUnixTime(issuedAt).ToString()) };


            JWTSecurityToken jwt = new JWTSecurityToken(issuer, audience, claims, null, issuedAt, expires);

            OpenIdConnectTokenRequestResponse tokenResponse = new OpenIdConnectTokenRequestResponse();

            string newAccessToken = GenerateOpenIdConnectToken();
            string newRefreshToken = GenerateOpenIdConnectToken();

            string jwtReadyToBeSent = jwtHandler.WriteToken(jwt);

            tokenResponse.access_token = newAccessToken;

            tokenResponse.expires_in = expiresIn.ToString();

            if (scopes.Contains("offline_access"))
            {
                tokenResponse.refresh_token = newRefreshToken.ToString();
            }
            else
            {
                tokenResponse.refresh_token = null;
            }


            tokenResponse.id_token = jwtReadyToBeSent;
            tokenResponse.token_type = "Bearer";
            //string serializedResponse = JsonConvert.SerializeObject(tokenResponse);

            return tokenResponse;
  

        }


          
        /// <summary>
        /// Returns a boolean indicating if the access is 
        /// </summary>
        /// <returns></returns>
        public static void ValidateOpenIdConnectRequest(HttpRequestBase httpRequest)
        {

            if (httpRequest == null)
            {
                throw new ApplicationException("HttpRequest is null");
            }

            string authorizationHeader = httpRequest.Headers["Authorization"];

            if (string.IsNullOrEmpty(authorizationHeader))
            {
                if (authorizationHeader.StartsWith("Bearer ", StringComparison.InvariantCultureIgnoreCase))
                {
                    string accessToken = ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(httpRequest.Headers["Authorization"].Substring(7)));


                    if (String.IsNullOrEmpty(accessToken))
                    {
                        throw new HttpException((int)HttpStatusCode.BadRequest, "The access token was not provided");
                    }
                    else
                    {
                        return;
                    }

                }
                else
                {
                    throw new HttpException((int)HttpStatusCode.BadRequest, "The authorization request only supports Bearer Token Usage");
                }
            }
            else
            {
                throw new HttpException((int)HttpStatusCode.BadRequest, "The Http authorization header was not provided");
            }
             
        }

    
            
        private static long ToUnixTime(DateTime date)
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); //small fix on EPOCH (add 1 second) to avoid iat being later than nbf
            return Convert.ToInt64((date.ToUniversalTime() - epoch).TotalSeconds);
        }

    
        /// <summary>
        /// Generates an 'almost' unique key and it is based on userId
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public static string GenerateOpenIdConnectCode(string userId)
        {
            Guid newGUID = Guid.NewGuid();
            StringBuilder buffer = new StringBuilder();
            foreach (Byte b in newGUID.ToByteArray())
            {
                buffer.AppendFormat("{0:X2}", b);
            }
            return buffer.ToString() + "-" + userId;
        }

        public static string GenerateOpenIdConnectToken()
        {
            return Guid.NewGuid().ToString();
        }

        public static byte[] GenerateSymmetricKeyForHmacSha256()
        {
            // Generate symmetric key for HMAC-SHA256 signature
            RNGCryptoServiceProvider cryptoProvider = new RNGCryptoServiceProvider();
            byte[] keyForHmacSha256 = new byte[64];
            cryptoProvider.GetNonZeroBytes(keyForHmacSha256);
            return keyForHmacSha256;
        }

        private class BasicHttpNetworkCredential
        {
            public string Id { get; set; }
            public string Password { get; set; }
        }

        private class BearerCredential
        {
            public string AccessToken { get; set; }
        }

        private static bool IsBasicAuthorization(HttpRequestBase request)
        {
            return (request.Headers["Authorization"].StartsWith("Basic ", StringComparison.InvariantCultureIgnoreCase));

        }

        private static bool IsBearerAuthorization(HttpRequestBase request)
        {
            return (request.Headers["Authorization"].StartsWith("Bearer ", StringComparison.InvariantCultureIgnoreCase));
        }

        private static BasicHttpNetworkCredential GetUserCredentialsFromRequest(HttpRequestBase request)
        {
            if (request == null)
            {
                throw new ApplicationException("The Http Request is null");
            }
            else
            {
                string authorizationHeader = request.Headers["Authorization"];
                if (string.IsNullOrEmpty(authorizationHeader))
                {
                    throw new HttpException((int)HttpStatusCode.BadRequest, "The Http authorization header was not provided");
                }
                else
                {
                    var cred = System.Text.ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(authorizationHeader.Substring(6))).Split(':');
                    BasicHttpNetworkCredential user = new BasicHttpNetworkCredential { Id = cred[0], Password = cred[1] };

                    return user;
                }
            }
        }

        private static BearerCredential GetBearerCredentialsFromRequest(HttpRequestBase request)
        {
             
            if (request == null)
            {
                throw new ApplicationException("The Http Request is null");
            }
            else
            {
                string authorizationHeader = request.Headers["Authorization"];
                if (string.IsNullOrEmpty(authorizationHeader))
                {
                    throw new HttpException((int)HttpStatusCode.BadRequest, "The Http authorization header was not provided");
                }
                else
                {
                    BearerCredential bearer = new BearerCredential() { AccessToken = ASCIIEncoding.ASCII.GetString(Convert.FromBase64String(authorizationHeader.Substring(7))) };
                    return bearer;
                }
            }

           
        }

        public static bool IsAuthorizationValid(HttpRequestBase request)
        {

            if (request == null)
            {
                return false;
            }
            else
            {
                string authorizationHeader = request.Headers["Authorization"];
                if (string.IsNullOrEmpty(authorizationHeader))
                {
                    return false;
                }
                else
                {
                    BasicHttpNetworkCredential clientCredentials = GetUserCredentialsFromRequest(request);

                    if (string.IsNullOrEmpty(clientCredentials.Id) || string.IsNullOrEmpty(clientCredentials.Password))
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
            }


        }

         

    }
}
