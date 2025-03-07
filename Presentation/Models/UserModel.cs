﻿namespace Presentation.Models
{
    public class UserModel
    {
        public string UserId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public List<TenantModel> Tenants { get; set; }
    }
}
