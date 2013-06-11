﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Alhambra.OAuth2OpenIdConnect.Models
{
    public class RegisteredUser
    {
        public string Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string FullName { get { return FirstName + " " + LastName; } }
        public string Profile { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
