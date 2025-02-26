using Domain.DomainEvents;
using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using SharedDomain.Common;
using System.Runtime.Serialization;
namespace Domain.Entities
{
    public class User : BaseEntity
    {
        public string Username { get; private set; }
        public byte[] PasswordHash { get; private set; }
        public byte[] PasswordSalt { get; private set; }
        
        public Email Email { get; private set; }
        public bool IsMfaEnabled { get; private set; }
        public string MfaSecretKey { get; private set; }

        // Navigation properties
        public List<UserTenant> UserTenants { get; private set; } = new List<UserTenant>();
        public List<UserRole> UserRoles { get; private set; } = new List<UserRole>();

        public User() { }

        public User(string username, Email email, byte[] passwordHash, byte[] passwordSalt)
        {
            Username = username;
            Email = email;
            PasswordHash = passwordHash;
            PasswordSalt = passwordSalt;
            IsMfaEnabled = false;
            MfaSecretKey = string.Empty;
        }

        public void EnableMfa(string secretKey)
        {
            IsMfaEnabled = true;
            MfaSecretKey = secretKey;
        }

        public void DisableMfa()
        {
            IsMfaEnabled = false;
            MfaSecretKey = string.Empty;
        }

        public void UpdatePassword(byte[] passwordHash, byte[] passwordSalt)
        {
            PasswordHash = passwordHash;
            PasswordSalt = passwordSalt;
        }

        public void UpdateEmail(string newEmail)
        {
            Email = new Email(newEmail);
        }

        public void UpdateUsername(string newUsername)
        {
            Username = newUsername;
        }

        public static void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        public void AddTenant(Tenant tenant, TenantRole role)
        {
            var userTenant = new UserTenant(this, tenant, role);
            UserTenants.Add(userTenant);
        }

        public void RemoveTenant(Tenant tenant)
        {
            UserTenants.RemoveAll(ut => ut.TenantId == tenant.Id);
        }
    }
}