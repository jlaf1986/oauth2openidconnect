using Microsoft.IdentityModel.Tokens.JWT;
using OAuth2OpenIdConnect.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OAuth2OpenIdConnect.Jwt
{
    public static class OpenIdConnectTokenHandler
    {
        public static void ValidateToken(OpenIdConnectToken token, OpenIdConnectTokenValidationParameters validationParams)
        {
            JWTSecurityToken securityToken = new JWTSecurityToken(token.IdToken);



            if (validationParams.ValidateIssuer)
            {
                if (securityToken.Issuer != validationParams.ValidIssuer)
                {
                    throw new ApplicationException("The audience is not valid");
                }
            }

            if (validationParams.ValidateNotBefore)
            {
                if (securityToken.ValidFrom > DateTime.UtcNow)
                {
                    throw new ApplicationException("The token is not currently valid");
                }
            }

            if (validationParams.ValidateExpiration)
            {

                DateTime currentTime = DateTime.UtcNow;

                if ((securityToken.ValidTo.ToUniversalTime() <= currentTime) || (currentTime> securityToken.ValidFrom.ToUniversalTime().Add(new TimeSpan(0,0,token.ExpiresIn))))
                {
                    throw new ApplicationException("The token is not valid anymore");
                }
            }



        }
    }
}
