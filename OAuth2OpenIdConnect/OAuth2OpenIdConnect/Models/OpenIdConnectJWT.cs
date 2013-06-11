using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Alhambra.OAuth2OpenIdConnect.Models
{
    public class OpenIdConnectJWT
    {
        public string Issuer { get; set; }
        public string Subject { get; set; }
        public string Audience { get; set; }
        public string ExpiresAt { get; set; }
        public string IssuedAt { get; set; }
    }
}
