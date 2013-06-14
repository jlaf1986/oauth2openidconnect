using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using OAuth2OpenIdConnect.Models;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net;
using System.Web;
using System.Net.Http.Formatting;


namespace OAuth2OpenIdConnect.Client
{
    public class OAuth2OpenIdConnectClient 
    {
        public OAuth2OpenIdConnectClient(string state)
        {
        }

        private string Code { get; set; }

        private string State { get; set; }

        public List<string> OpenIdScopes { get; set; }

        public Uri AuthUrl { get; set; }

        public Uri TokenUrl { get; set; }

        public Uri ClientCallbackUrl { get; set; }

        public string ClientIdentifier { get; set; }

        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets representation of the result from the server
        /// </summary>
        /// <param name="RequestAddress"></param>
        /// <param name="scopes"></param>
        /// <returns></returns>
        public T GetDataRequestResponse<T>(Uri RequestAddress, string scopes)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets the token from the server
        /// </summary>
        /// <param name="code"></param>
        /// <returns></returns>
        public OpenIdConnectToken GetTokenRequestResponse(string code)
        {
          // OpenIdConnectTokenRequestResponse response = new OpenIdConnectAuthorizationRequestResponse();
            OpenIdConnectToken result = new OpenIdConnectToken();


           
            var httpClient = new HttpClient();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", this.ClientSecret);
             
            Dictionary<string, string> formVals = new Dictionary<string, string>();
            formVals.Add("grant_type", "authorization_code");
            formVals.Add("code", code);

            formVals.Add("redirect_uri", ClientCallbackUrl.ToString());


            HttpRequestMessage postRequest = new HttpRequestMessage(HttpMethod.Post, TokenUrl.ToString());
            postRequest.Content = new FormUrlEncodedContent(formVals);

            HttpResponseMessage postResponse = httpClient.SendAsync(postRequest).Result;


            OpenIdConnectTokenRequestResponse tokenResponse = postResponse.Content.ReadAsAsync<OpenIdConnectTokenRequestResponse>().Result;

            result.AccessToken = tokenResponse.access_token;

            result.RefreshToken = tokenResponse.refresh_token;

            result.ExpiresIn = int.Parse(tokenResponse.expires_in);

            result.IdToken = tokenResponse.id_token;


            return result;
        }

        /// <summary>
        /// Gets the authorization response from the server
        /// </summary>
        /// <returns></returns>
        public void SendAuthorizationRequest()
        {
            var httpClient = new HttpClient();
           // httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", this.ClientSecret);

            var authRequestUrl = AuthUrl.ToString() +
                "?response_type=code" +
                "&client_id=" + ClientIdentifier +
                "&redirect_uri=" + ClientCallbackUrl.ToString() +
                "&scope=" + OpenIdScopes +
                "&state=" + State;

            HttpRequestMessage postRequest = new HttpRequestMessage(HttpMethod.Post, authRequestUrl);
            //getRequest.Content = new FormUrlEncodedContent(formVals);
             
            HttpResponseMessage postResponse = httpClient.SendAsync(postRequest).Result;
             
        }

    }
}
