using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuth2OpenIdConnect.Models
{
    public class OpenIdConnectTokenValidationParameters
    {
        public string AllowedAudience { get; set; }
        public string ValidIssuer { get; set; }
        public bool ValidateExpiration { get; set; }
        public bool ValidateNotBefore { get; set; }
        public bool ValidateIssuer { get; set; }
    }
}
