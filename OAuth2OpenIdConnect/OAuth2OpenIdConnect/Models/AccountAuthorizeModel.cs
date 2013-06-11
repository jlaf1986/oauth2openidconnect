using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Alhambra.OAuth2OpenIdConnect.Models
{
   

    public class AlhambraOAuth2Authorization
    {
        public string UserId { get; set; }

        public string ClientIdentifier { get; set; }

        public DateTime AuthorizedAt { get; set; }

        public DateTime ExpiresAt { get; set; }

        public string AccessToken { get; set; }

        public string RefreshToken { get; set; }

        public string Code { get; set; }

        public string Scope { get; set; }

        public string State { get; set; }

        public OpenIdConnectAuthorizationRequest AuthorizationRequest { get; set; }

    }
}
