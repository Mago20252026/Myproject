// File: AuthenticationApplicationService.cs

using Infrastructure.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.ApplicationServices
{
    public class AuthenticationApplicationService
    {
        private readonly AuthenticationService _authenticationService;
        private readonly JwtTokenService _jwtTokenService;
        private readonly MfaService _mfaService;

        public AuthenticationApplicationService(AuthenticationService authenticationService, JwtTokenService jwtTokenService, MfaService mfaService)
        {
            _authenticationService = authenticationService;
            _jwtTokenService = jwtTokenService;
            _mfaService = mfaService;
        }

        public async Task<string> Login(string username, string password)
        {
            var user = await _authenticationService.Authenticate(username, password);
            if (user == null)
               throw  new Exception("Invalid username or password.");

            if (user.IsMfaEnabled)
            {
                await _mfaService.SendMfaCode(user);
                throw new InvalidOperationException("MFA code required.");
            }

            return _jwtTokenService.GenerateToken(user);
        }

        public async Task<string> VerifyMfa(string username, string mfaCode)
        {
            var user = await _authenticationService.GetUserByUsername(username);
            if (user == null || !_mfaService.VerifyMfaCode(user, mfaCode))
                throw new UnauthorizedAccessException("Invalid MFA code.");

            return _jwtTokenService.GenerateToken(user);
        }

        public async Task<string> Register(string username, string email, string password)
        {
            var user = await _authenticationService.Register(username, email, password);
            return _jwtTokenService.GenerateToken(user);
        }

        public async Task RevokeToken(string token)
        {
            await _jwtTokenService.RevokeToken(token);
        }

        public async Task<string> RefreshToken(string token)
        {
            return await _jwtTokenService.RefreshToken(token);
        }
    }
}

--------------------------------------------------------------------------------

// File: RoleApplicationService.cs

using Domain.Entities;
using Domain.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.ApplicationServices
{
    public class RoleApplicationService
    {
        private readonly IRoleRepository _roleRepository;
        private readonly ITenantRepository _tenantRepository;

        public RoleApplicationService(IRoleRepository roleRepository, ITenantRepository tenantRepository)
        {
            _roleRepository = roleRepository;
            _tenantRepository = tenantRepository;
        }

        public async Task CreateRole(string tenantId, string roleName, List<string> permissions)
        {
            var role = new Role(roleName, permissions);
            await _roleRepository.AddAsync(role);
        }

        public async Task UpdateRolePermissions(Guid roleId, List<string> permissions)
        {
            var role = await _roleRepository.GetByIdAsync(roleId);
            role.UpdatePermissions(permissions);
            await _roleRepository.UpdateAsync(role);
        }

        public async Task DeleteRole(Guid roleId)
        {
            await _roleRepository.DeleteAsync(roleId);
        }
    }
}

--------------------------------------------------------------------------------

// File: TenantApplicationService.cs

using Application.DTOs;
using Domain.Entities;
using Domain.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.ApplicationServices
{
    public class TenantApplicationService
    {
        private readonly ITenantRepository _tenantRepository;

        public TenantApplicationService(ITenantRepository tenantRepository)
        {
            _tenantRepository=tenantRepository;
        }

        public async Task CreateTenant(CreateTenantRequest request) 
        {
            var tenant = new Tenant(request.Name);
            await _tenantRepository.AddAsync(tenant);
        }

        public async Task UpdateTenant(UpdateTenantRequest request)
        {
            var tenant = await _tenantRepository.GetByIdAsync(request.TenantId);
            tenant.UpdateName(request.Name);
            await _tenantRepository.UpdateAsync(tenant);
        }

        public async Task DeleteTenant(DeleteTenantRequest request) 
        {
            await _tenantRepository.DeleteAsync(request.TenantId);
        }
    }
}


--------------------------------------------------------------------------------

// File: UserApplicationService.cs

using Application.DTOs;
using Domain.Entities;
using Domain.Repositories;
using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.ApplicationServices
{
    public class UserApplicationService
    {
        private readonly IUserRepository _userRepository;
        private readonly ITenantRepository _tenantRepository;

        public UserApplicationService(IUserRepository userRepository, ITenantRepository tenantRepository)
        {
            _userRepository = userRepository;
            _tenantRepository = tenantRepository;
        }

        public async Task RegisterUser(RegisterUserRequest request)
        {
            var email = new Email(request.Email);
            var user = new User(request.Username, email, new byte[0], new byte[0]); // Add proper password hashing

            await _userRepository.AddAsync(user);

            foreach (var tenantId in request.TenantIds)
            {
                var tenant = await _tenantRepository.GetByIdAsync(tenantId);
                user.AddTenant(tenant, request.Role); // Correct method call
            }
            await _userRepository.UpdateAsync(user);
        }

        public async Task AddUserToTenant(AddUserToTenantRequest request)
        {
            var user = await _userRepository.GetByIdAsync(request.UserId);
            var tenant = await _tenantRepository.GetByIdAsync(request.TenantId);
            user.AddTenant(tenant, request.Role); // Correct method call

            await _userRepository.UpdateAsync(user);
        }

        public async Task RemoveUserFromTenant(RemoveUserFromTenantRequest request)
        {
            var user = await _userRepository.GetByIdAsync(request.UserId);
            var tenant = await _tenantRepository.GetByIdAsync(request.TenantId);
            user.RemoveTenant(tenant); // Correct method call

            await _userRepository.UpdateAsync(user);
        }
    }
}

--------------------------------------------------------------------------------

// File: UserProfileApplicationService.cs

using Domain.Entities;
using Domain.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.ApplicationServices
{
    public class UserProfileApplicationService
    {
        private readonly IUserRepository _userRepository;

        public UserProfileApplicationService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        public async Task UpdateUserProfile(Guid userId, string newEmail, string newUsername)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            user.UpdateEmail(newEmail);
            user.UpdateUsername(newUsername);
            await _userRepository.UpdateAsync(user);
        }

        public async Task UpdatePassword(Guid userId, string newPassword)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            byte[] passwordHash, passwordSalt;
            User.CreatePasswordHash(newPassword, out passwordHash, out passwordSalt);
            user.UpdatePassword(passwordHash, passwordSalt);
            await _userRepository.UpdateAsync(user);
        }

        public async Task EnableMfa(Guid userId, string secretKey)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            user.EnableMfa(secretKey);
            await _userRepository.UpdateAsync(user);
        }

        public async Task DisableMfa(Guid userId)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            user.DisableMfa();
            await _userRepository.UpdateAsync(user);
        }
    }
}

--------------------------------------------------------------------------------

// File: AddUserToTenantRequest.cs

using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class AddUserToTenantRequest
    {
        public Guid UserId { get; set; }
        public Guid TenantId { get; set; }
        public TenantRole Role { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: CreateRoleRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class CreateRoleRequest
    {
        public string TenantId { get; set; }
        public string RoleName { get; set; }
        public List<string> Permissions { get; set; }
    }
}

--------------------------------------------------------------------------------

// File: CreateTenantRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class CreateTenantRequest
    {
        public string Name { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: DeleteRoleRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class DeleteRoleRequest
    {
        public Guid RoleId { get; set; }
    }
}

--------------------------------------------------------------------------------

// File: DeleteTenantRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class DeleteTenantRequest
    {
        public Guid TenantId { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: DisableMfaRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class DisableMfaRequest
    {
        public Guid UserId { get; set; }
    }
}

--------------------------------------------------------------------------------

// File: EnableMfaRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class EnableMfaRequest
    {
        public Guid UserId { get; set; }
        public string SecretKey { get; set; }
    }
}

--------------------------------------------------------------------------------

// File: LoginRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: RefreshTokenRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class RefreshTokenRequest
    {
        public string Token { get; set; }
    }
}

--------------------------------------------------------------------------------

// File: RegisterRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class RegisterRequest
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: RegisterUserRequest.cs

using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class RegisterUserRequest
    {
        public string Username { get; set; }
        public string Email {  get; set; }
        public List<Guid> TenantIds {  get; set; }
        public TenantRole Role { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: RemoveUserFromTenantRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class RemoveUserFromTenantRequest
    {
        public Guid UserId { get; set; }
        public Guid TenantId { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: RevokeTokenRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class RevokeTokenRequest
    {
        public string Token { get; set; }
    }
}

--------------------------------------------------------------------------------

// File: SecurityEventRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class SecurityEventRequest
    {
        public string EventType { get; set; }
        public string Details { get; set; }
    }
}

--------------------------------------------------------------------------------

// File: UpdatePasswordRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class UpdatePasswordRequest
    {
        public Guid UserId { get; set; }
        public string NewPassword { get; set; }
    }
}

--------------------------------------------------------------------------------

// File: UpdateRolePermissionsRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class UpdateRolePermissionsRequest
    {
        public Guid RoleId { get; set; }
        public List<string> Permissions { get; set; }
    }
}

--------------------------------------------------------------------------------

// File: UpdateTenantRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class UpdateTenantRequest
    {
        public Guid TenantId { get; set; }
        public string Name { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: UpdateUserProfileRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class UpdateUserProfileRequest
    {
        public Guid UserId { get; set; }
        public string NewEmail { get; set; }
        public string NewUsername { get; set; }
    }
}

--------------------------------------------------------------------------------

// File: VerifyMfaRequest.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.DTOs
{
    public class VerifyMfaRequest
    {
        public string Username { get; set; }
        public string MfaCode { get; set; }
    }
}

--------------------------------------------------------------------------------

// File: RoleBasedAccessControl.cs

using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Security
{
    public class RoleBasedAccessControl
    {
         private readonly Dictionary<TenantRole, List<string>> _rolePermissions;

        public RoleBasedAccessControl()
        {
            _rolePermissions = new Dictionary<TenantRole, List<string>>
            {
                { TenantRole.SuperAdmin, new List<string> { "ManageTenants", "ManageUsers", "ViewReports" } },
                { TenantRole.TenantAdmin, new List<string> { "ManageUsers", "AssignRoles" } },
                { TenantRole.User, new List<string> { "ViewContent" } }
            };
        }

        public bool HasPermission(TenantRole role, string permission)
        {
            if (_rolePermissions.TryGetValue(role, out var permissions))
            {
                return permissions.Contains(permission);
            }

            return false;
        }
    }
}


--------------------------------------------------------------------------------

// File: TenantAggregate.cs

using Domain.Entities;
using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Aggregates
{
    public class TenantAggregate
    {
        public Tenant Tenant {  get; private set; }
        public List<User> Users { get; private set; }

        public TenantAggregate(Tenant tenant) 
        {
            Tenant = tenant;
            Users = new List<User>();
        }

        public void AddUser(User user, TenantRole role)
        {
           Tenant.AddUser(user, role);
            if (!Users.Contains(user))
            {
                Users.Add(user);
            }
        }
        public void RemoveUser(User user) { 
            Tenant.UserTenants.RemoveAll(ut => ut.User.Id == user.Id);
            Users.Remove(user);
        }
    }
}


--------------------------------------------------------------------------------

// File: UserAggregate.cs

using Domain.Entities;
using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Aggregates
{
    public class UserAggregate
    {
        public User User { get; private set; }
        public List<UserTenant> UserTenants => User.UserTenants;

        public UserAggregate(User user)
        {
            User = user;
        }

        public void UpdateEmail(string newEmail)
        {
        }

        public void UpdateUsername(string newUsername)
        {
        }

    }
}


--------------------------------------------------------------------------------

// File: TenantCreatedEvent.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.DomainEvents
{
    public class TenantCreatedEvent
    {
        public Guid TenantId { get; private set;}
        public string TenantName {  get; private set;}

        public TenantCreatedEvent(Guid tenantId, string tenantName)
        {
            TenantId=tenantId;
            TenantName=tenantName;
        }
    }
}


--------------------------------------------------------------------------------

// File: UserRegisteredEvent .cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.DomainEvents
{
    public class UserRegisteredEvent 
    {
        public Guid UserId { get; private set; }
        public string UserName { get; private set; }
        public string Email { get; private set; }

        public UserRegisteredEvent(Guid userId, string username, string email)
        {
            UserId = userId;
            UserName = username;
            Email = email;
        }
    }
}


--------------------------------------------------------------------------------

// File: TenantManagementService.cs

using Domain.Entities;
using Domain.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.DomainServices
{
    public class TenantManagementService
    {
        private readonly ITenantRepository _tenantRepository;

        public TenantManagementService(ITenantRepository tenantRepository)
        {
            _tenantRepository = tenantRepository;
        }

        public async Task CreateTenantAsync(Tenant tenant)
        {
            await _tenantRepository.AddAsync(tenant);
        }

        public async Task UpdateTenantAsync(Tenant tenant)
        {
            await _tenantRepository.UpdateAsync(tenant);
        }

        public async Task DeleteTenantAsync(Guid tenantId)
        {
            await _tenantRepository.DeleteAsync(tenantId);
        }
    }
}

--------------------------------------------------------------------------------

// File: UserManagementService.cs

using Domain.Entities;
using Domain.Repositories;
using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.DomainServices
{
    public class UserManagementService
    {
        private readonly IUserRepository _userRepository;
        private readonly ITenantRepository _tenantRepository;

        public UserManagementService(IUserRepository userRepository, ITenantRepository tenantRepository)
        {
            _userRepository = userRepository;
            _tenantRepository = tenantRepository;
        }

        public async Task RegisterUserAsync(User user)
        {
            await _userRepository.AddAsync(user);
        }

        public async Task AddUserToTenantAsync(User user, Tenant tenant, TenantRole role)
        {
            user.AddTenant(tenant, role);
            await _userRepository.UpdateAsync(user);
        }

        public async Task RemoveUserFromTenantAsync(User user, Tenant tenant)
        {
            user.RemoveTenant(tenant);
            await _userRepository.UpdateAsync(user);
        }
    }
}

--------------------------------------------------------------------------------

// File: Role.cs

using SharedDomain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Entities
{
    public class Role : BaseEntity
    {
        public string Name { get; private set; }
        public List<string> Permissions { get; private set; }

        public List<UserRole> UserRoles { get; private set; } = new List<UserRole>();


        public Role(string name, List<string> permissions)
        {
            Name = name;
            Permissions = permissions;
        }

        public void UpdatePermissions(List<string> permissions)
        {
            Permissions = permissions;
        }
    }
}

--------------------------------------------------------------------------------

// File: Tenant.cs

using Domain.ValueObjects;
using SharedDomain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Entities
{
    public class Tenant : BaseEntity
    {
        public string Name { get; private set; }

        public List<UserTenant> UserTenants { get; private set; } = new List<UserTenant>();


        public Tenant(string name)
        {
            Name = name;
        }

        public void AddUser(User user, TenantRole role)
        {
            var userTenant = new UserTenant(user, this, role);
            UserTenants.Add(userTenant);
        }

        public void UpdateName(string name)
        {
            Name = name;
        }
    }
}

--------------------------------------------------------------------------------

// File: User.cs

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

--------------------------------------------------------------------------------

// File: UserRole.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharedDomain.Common;

namespace Domain.Entities
{
    public class UserRole : BaseEntity
    {
        public Guid UserId { get; private set; }
        public Guid RoleId { get; private set; }
        public Guid TenantId { get; private set; }

        public User User { get; private set; }
        public Role Role { get; private set; }
        public Tenant Tenant { get; private set; }


        public UserRole(Guid userId, Guid roleId, Guid tenantId)
        {
            UserId = userId;
            RoleId = roleId;
            TenantId = tenantId;
        }
    }
}

--------------------------------------------------------------------------------

// File: UserTenant.cs

using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharedDomain.Common;

namespace Domain.Entities
{
    public class UserTenant : BaseEntity
    {


        public Guid UserId { get; private set; }
        public Guid TenantId { get; private set; }

        public User User { get; private set; }
        public Tenant Tenant { get; private set; }
        public TenantRole Role { get; private set; }


        public UserTenant(User user, Tenant tenant, TenantRole role)
        {
            User = user;
            Tenant = tenant;
            Role = role;
            UserId = user.Id;
            TenantId = tenant.Id;
        }
    }
}


--------------------------------------------------------------------------------

// File: IRoleRepository.cs

using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Repositories
{
    public interface IRoleRepository
    {
        Task<Role> GetByIdAsync(Guid id);
        Task AddAsync(Role role);
        Task UpdateAsync(Role role);
        Task DeleteAsync(Guid id);
    }
}

--------------------------------------------------------------------------------

// File: ITenantRepository.cs

using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Repositories
{
    public interface ITenantRepository
    {
        Task<Tenant> GetByIdAsync(Guid id);
        Task AddAsync(Tenant tenant);
        Task UpdateAsync(Tenant tenant);
        Task DeleteAsync(Guid id);
    }
}


--------------------------------------------------------------------------------

// File: IUserRepository.cs

using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.Repositories
{
    public interface IUserRepository
    {
        Task<User> GetByIdAsync(Guid id);
        Task AddAsync(User user);
        Task DeleteAsync(Guid id);
        Task UpdateAsync(User user);
        Task<User> GetByUsernameAsync(string username);
        Task<bool> UserExists(string username, string email);
    }
}

--------------------------------------------------------------------------------

// File: Email.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Domain.ValueObjects
{
    public class Email
    {
        public string Value { get; private init; }

        public Email(string value)
        {
            if (!Regex.IsMatch(value, @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"))
                throw new Exception("Invalid email format.");

            Value = value;
        }

        public override string ToString()
        {
            return Value;
        }
    }
}

--------------------------------------------------------------------------------

// File: PhoneNumber.cs

using System;

namespace Domain.ValueObjects
{
    public class PhoneNumber
    {
        public string Value { get; private set; }

        public PhoneNumber(string value)
        {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentException("Phone number cannot be empty", nameof(value));
            if (!System.Text.RegularExpressions.Regex.IsMatch(value, @"^\+?[1-9]\d{1,14}$"))
                throw new ArgumentException("Invalid phone number format", nameof(value));

            Value = value;
        }

        public override string ToString()
        {
            return Value;
        }
    }
}

--------------------------------------------------------------------------------

// File: TenantRole.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Domain.ValueObjects
{
    public enum TenantRole
    {
        SuperAdmin,
        TenantAdmin,
        User
    }
}


--------------------------------------------------------------------------------

// File: 20250221161238_InitialCreate.cs

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Roles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Permissions = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Roles", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Tenants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Tenants", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Users",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Username = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    PasswordHash = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    PasswordSalt = table.Column<byte[]>(type: "varbinary(max)", nullable: false),
                    Email_Value = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    IsMfaEnabled = table.Column<bool>(type: "bit", nullable: false),
                    MfaSecretKey = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Users", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserRoles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserRoles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UserRoles_Roles_RoleId",
                        column: x => x.RoleId,
                        principalTable: "Roles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserRoles_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserRoles_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "UserTenants",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Role = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserTenants", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UserTenants_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserTenants_Users_UserId",
                        column: x => x.UserId,
                        principalTable: "Users",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Tenants_Name",
                table: "Tenants",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserRoles_RoleId",
                table: "UserRoles",
                column: "RoleId");

            migrationBuilder.CreateIndex(
                name: "IX_UserRoles_TenantId",
                table: "UserRoles",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_UserRoles_UserId",
                table: "UserRoles",
                column: "UserId");

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email_Value",
                table: "Users",
                column: "Email_Value",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserTenants_TenantId",
                table: "UserTenants",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_UserTenants_UserId",
                table: "UserTenants",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UserRoles");

            migrationBuilder.DropTable(
                name: "UserTenants");

            migrationBuilder.DropTable(
                name: "Roles");

            migrationBuilder.DropTable(
                name: "Tenants");

            migrationBuilder.DropTable(
                name: "Users");
        }
    }
}


--------------------------------------------------------------------------------

// File: 20250221161238_InitialCreate.Designer.cs

// <auto-generated />
using System;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace Infrastructure.Migrations
{
    [DbContext(typeof(AppDbContext))]
    [Migration("20250221161238_InitialCreate")]
    partial class InitialCreate
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "9.0.2")
                .HasAnnotation("Relational:MaxIdentifierLength", 128);

            SqlServerModelBuilderExtensions.UseIdentityColumns(modelBuilder);

            modelBuilder.Entity("Domain.Entities.Role", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.PrimitiveCollection<string>("Permissions")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("Id");

                    b.ToTable("Roles");
                });

            modelBuilder.Entity("Domain.Entities.Tenant", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("nvarchar(450)");

                    b.HasKey("Id");

                    b.HasIndex("Name")
                        .IsUnique();

                    b.ToTable("Tenants");
                });

            modelBuilder.Entity("Domain.Entities.User", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<bool>("IsMfaEnabled")
                        .HasColumnType("bit");

                    b.Property<string>("MfaSecretKey")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<byte[]>("PasswordHash")
                        .IsRequired()
                        .HasColumnType("varbinary(max)");

                    b.Property<byte[]>("PasswordSalt")
                        .IsRequired()
                        .HasColumnType("varbinary(max)");

                    b.Property<string>("Username")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("Id");

                    b.ToTable("Users");
                });

            modelBuilder.Entity("Domain.Entities.UserRole", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<Guid>("RoleId")
                        .HasColumnType("uniqueidentifier");

                    b.Property<Guid>("TenantId")
                        .HasColumnType("uniqueidentifier");

                    b.Property<Guid>("UserId")
                        .HasColumnType("uniqueidentifier");

                    b.HasKey("Id");

                    b.HasIndex("RoleId");

                    b.HasIndex("TenantId");

                    b.HasIndex("UserId");

                    b.ToTable("UserRoles");
                });

            modelBuilder.Entity("Domain.Entities.UserTenant", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<int>("Role")
                        .HasColumnType("int");

                    b.Property<Guid>("TenantId")
                        .HasColumnType("uniqueidentifier");

                    b.Property<Guid>("UserId")
                        .HasColumnType("uniqueidentifier");

                    b.HasKey("Id");

                    b.HasIndex("TenantId");

                    b.HasIndex("UserId");

                    b.ToTable("UserTenants");
                });

            modelBuilder.Entity("Domain.Entities.User", b =>
                {
                    b.OwnsOne("Domain.ValueObjects.Email", "Email", b1 =>
                        {
                            b1.Property<Guid>("UserId")
                                .HasColumnType("uniqueidentifier");

                            b1.Property<string>("Value")
                                .IsRequired()
                                .HasColumnType("nvarchar(450)");

                            b1.HasKey("UserId");

                            b1.HasIndex("Value")
                                .IsUnique();

                            b1.ToTable("Users");

                            b1.WithOwner()
                                .HasForeignKey("UserId");
                        });

                    b.Navigation("Email")
                        .IsRequired();
                });

            modelBuilder.Entity("Domain.Entities.UserRole", b =>
                {
                    b.HasOne("Domain.Entities.Role", "Role")
                        .WithMany("UserRoles")
                        .HasForeignKey("RoleId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("Domain.Entities.Tenant", "Tenant")
                        .WithMany()
                        .HasForeignKey("TenantId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("Domain.Entities.User", "User")
                        .WithMany("UserRoles")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("Role");

                    b.Navigation("Tenant");

                    b.Navigation("User");
                });

            modelBuilder.Entity("Domain.Entities.UserTenant", b =>
                {
                    b.HasOne("Domain.Entities.Tenant", "Tenant")
                        .WithMany("UserTenants")
                        .HasForeignKey("TenantId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("Domain.Entities.User", "User")
                        .WithMany("UserTenants")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("Tenant");

                    b.Navigation("User");
                });

            modelBuilder.Entity("Domain.Entities.Role", b =>
                {
                    b.Navigation("UserRoles");
                });

            modelBuilder.Entity("Domain.Entities.Tenant", b =>
                {
                    b.Navigation("UserTenants");
                });

            modelBuilder.Entity("Domain.Entities.User", b =>
                {
                    b.Navigation("UserRoles");

                    b.Navigation("UserTenants");
                });
#pragma warning restore 612, 618
        }
    }
}


--------------------------------------------------------------------------------

// File: AppDbContextModelSnapshot.cs

// <auto-generated />
using System;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace Infrastructure.Migrations
{
    [DbContext(typeof(AppDbContext))]
    partial class AppDbContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "9.0.2")
                .HasAnnotation("Relational:MaxIdentifierLength", 128);

            SqlServerModelBuilderExtensions.UseIdentityColumns(modelBuilder);

            modelBuilder.Entity("Domain.Entities.Role", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.PrimitiveCollection<string>("Permissions")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("Id");

                    b.ToTable("Roles");
                });

            modelBuilder.Entity("Domain.Entities.Tenant", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasColumnType("nvarchar(450)");

                    b.HasKey("Id");

                    b.HasIndex("Name")
                        .IsUnique();

                    b.ToTable("Tenants");
                });

            modelBuilder.Entity("Domain.Entities.User", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<bool>("IsMfaEnabled")
                        .HasColumnType("bit");

                    b.Property<string>("MfaSecretKey")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.Property<byte[]>("PasswordHash")
                        .IsRequired()
                        .HasColumnType("varbinary(max)");

                    b.Property<byte[]>("PasswordSalt")
                        .IsRequired()
                        .HasColumnType("varbinary(max)");

                    b.Property<string>("Username")
                        .IsRequired()
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("Id");

                    b.ToTable("Users");
                });

            modelBuilder.Entity("Domain.Entities.UserRole", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<Guid>("RoleId")
                        .HasColumnType("uniqueidentifier");

                    b.Property<Guid>("TenantId")
                        .HasColumnType("uniqueidentifier");

                    b.Property<Guid>("UserId")
                        .HasColumnType("uniqueidentifier");

                    b.HasKey("Id");

                    b.HasIndex("RoleId");

                    b.HasIndex("TenantId");

                    b.HasIndex("UserId");

                    b.ToTable("UserRoles");
                });

            modelBuilder.Entity("Domain.Entities.UserTenant", b =>
                {
                    b.Property<Guid>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("uniqueidentifier");

                    b.Property<int>("Role")
                        .HasColumnType("int");

                    b.Property<Guid>("TenantId")
                        .HasColumnType("uniqueidentifier");

                    b.Property<Guid>("UserId")
                        .HasColumnType("uniqueidentifier");

                    b.HasKey("Id");

                    b.HasIndex("TenantId");

                    b.HasIndex("UserId");

                    b.ToTable("UserTenants");
                });

            modelBuilder.Entity("Domain.Entities.User", b =>
                {
                    b.OwnsOne("Domain.ValueObjects.Email", "Email", b1 =>
                        {
                            b1.Property<Guid>("UserId")
                                .HasColumnType("uniqueidentifier");

                            b1.Property<string>("Value")
                                .IsRequired()
                                .HasColumnType("nvarchar(450)");

                            b1.HasKey("UserId");

                            b1.HasIndex("Value")
                                .IsUnique();

                            b1.ToTable("Users");

                            b1.WithOwner()
                                .HasForeignKey("UserId");
                        });

                    b.Navigation("Email")
                        .IsRequired();
                });

            modelBuilder.Entity("Domain.Entities.UserRole", b =>
                {
                    b.HasOne("Domain.Entities.Role", "Role")
                        .WithMany("UserRoles")
                        .HasForeignKey("RoleId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("Domain.Entities.Tenant", "Tenant")
                        .WithMany()
                        .HasForeignKey("TenantId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("Domain.Entities.User", "User")
                        .WithMany("UserRoles")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("Role");

                    b.Navigation("Tenant");

                    b.Navigation("User");
                });

            modelBuilder.Entity("Domain.Entities.UserTenant", b =>
                {
                    b.HasOne("Domain.Entities.Tenant", "Tenant")
                        .WithMany("UserTenants")
                        .HasForeignKey("TenantId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("Domain.Entities.User", "User")
                        .WithMany("UserTenants")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("Tenant");

                    b.Navigation("User");
                });

            modelBuilder.Entity("Domain.Entities.Role", b =>
                {
                    b.Navigation("UserRoles");
                });

            modelBuilder.Entity("Domain.Entities.Tenant", b =>
                {
                    b.Navigation("UserTenants");
                });

            modelBuilder.Entity("Domain.Entities.User", b =>
                {
                    b.Navigation("UserRoles");

                    b.Navigation("UserTenants");
                });
#pragma warning restore 612, 618
        }
    }
}


--------------------------------------------------------------------------------

// File: AppDbContext.cs

using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Persistence
{
    public class AppDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<Tenant> Tenants { get; set; }
        public DbSet<UserTenant> UserTenants { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<UserRole> UserRoles { get; set; }

        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure EmailAddress as an owned type
            modelBuilder.Entity<User>(entity =>
            {
                entity.OwnsOne(u => u.Email, entity =>
                {
                    // Add a unique constraint on the Email column
                    entity.HasIndex(u => u.Value).IsUnique();
                });
            });

            // Configure UserTenant relationships
            modelBuilder.Entity<UserTenant>()
                .HasKey(ut => ut.Id); // Primary key

            modelBuilder.Entity<UserTenant>()
                .HasOne(ut => ut.User)
                .WithMany(u => u.UserTenants)
                .HasForeignKey(ut => ut.UserId);

            modelBuilder.Entity<UserTenant>()
                .HasOne(ut => ut.Tenant)
                .WithMany(t => t.UserTenants)
                .HasForeignKey(ut => ut.TenantId);

            // Configure UserRole relationships
            modelBuilder.Entity<UserRole>()
                .HasKey(ur => ur.Id); // Primary key

            modelBuilder.Entity<UserRole>()
                .HasOne(ur => ur.User)
                .WithMany(u => u.UserRoles)
                .HasForeignKey(ur => ur.UserId);

            modelBuilder.Entity<UserRole>()
                .HasOne(ur => ur.Role)
                .WithMany(r => r.UserRoles)
                .HasForeignKey(ur => ur.RoleId);

            // Additional configurations
     

            modelBuilder.Entity<Tenant>()
                .HasIndex(t => t.Name)
                .IsUnique();
        }
    }
}

--------------------------------------------------------------------------------

// File: RoleRepository.cs

using Domain.Entities;
using Domain.Repositories;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Persistence.Repositories
{
    public class RoleRepository : IRoleRepository
    {
        private readonly AppDbContext _context;

        public RoleRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task<Role> GetByIdAsync(Guid id)
        {
            return await _context.Roles.Include(r => r.UserRoles).FirstOrDefaultAsync(r => r.Id == id);
        }

        public async Task AddAsync(Role role)
        {
            await _context.Roles.AddAsync(role);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(Role role)
        {
            _context.Roles.Update(role);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(Guid id)
        {
            var role = await GetByIdAsync(id);
            if (role != null)
            {
                _context.Roles.Remove(role);
                await _context.SaveChangesAsync();
            }
        }
    }
}

--------------------------------------------------------------------------------

// File: TenantRepository.cs

using Domain.Entities;
using Domain.Repositories;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Persistence.Repositories
{
    public class TenantRepository : ITenantRepository
    {
        private readonly AppDbContext _context;

        public TenantRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task<Tenant> GetByIdAsync(Guid tenantId)
        {
            return await _context.Tenants.Include(t => t.UserTenants).FirstOrDefaultAsync(t => t.Id == tenantId);
        }

        public async Task AddAsync(Tenant tenant)
        {
            await _context.Tenants.AddAsync(tenant);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(Tenant tenant)
        {
            _context.Tenants.Update(tenant);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(Guid id)
        {
            var tenant = await GetByIdAsync(id);
            if (tenant != null)
            {
                _context.Tenants.Remove(tenant);
                await _context.SaveChangesAsync();
            }
        }
    }
}

--------------------------------------------------------------------------------

// File: UserRepository.cs

using Domain.Entities;
using Domain.Repositories;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Persistence.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly AppDbContext _context;

        public UserRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task AddAsync(User user)
        {
            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(Guid id)
        {
            var user = await GetByIdAsync(id);
            if (user != null)
            {
                _context.Users.Remove(user);
                await _context.SaveChangesAsync();
            }
        }

        public async Task<User> GetByIdAsync(Guid id)
        {
            return await _context.Users.Include(u => u.UserTenants).FirstOrDefaultAsync(u => u.Id == id);
        }

        public async Task UpdateAsync(User user)
        {
            _context.Users.Update(user);
            await _context.SaveChangesAsync();
        }

        public async Task<User> GetByUsernameAsync(string username)
        {
            return await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        }

        public async Task<bool> UserExists(string username, string email)
        {
            return await _context.Users.AnyAsync(u => u.Username == username || u.Email.ToString() == email);
        }
    }
}

--------------------------------------------------------------------------------

// File: AuthenticationService.cs

using Domain.Entities;
using Domain.Repositories;
using Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Security
{
    public class AuthenticationService
    {
        private readonly IUserRepository _userRepository;

        public AuthenticationService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        public async Task<User> Authenticate(string username, string password)
        {
            var user = await _userRepository.GetByUsernameAsync(username);
            if (user == null || !VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
                return null;

            return user;
        }

        public async Task<User> Register(string username, string email, string password)
        {
            if (await _userRepository.UserExists(username, email))
                throw new InvalidOperationException("User already exists.");

            byte[] passwordHash, passwordSalt;
            User.CreatePasswordHash(password, out passwordHash, out passwordSalt);

            var user = new User(username, new Email(email), passwordHash, passwordSalt);
            await _userRepository.AddAsync(user);

            return user;
        }

        private bool VerifyPasswordHash(string password, byte[] storedHash, byte[] storedSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512(storedSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(storedHash);
            }
        }

        public async Task<User> GetUserByUsername(string username)
        {
            return await _userRepository.GetByUsernameAsync(username);
        }
    }
}

--------------------------------------------------------------------------------

// File: JwtTokenService.cs

using Domain.Entities;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Security
{
    public class JwtTokenService
    {
        private readonly string _secret;
        private readonly string _issuer;
        private readonly string _audience;
        private readonly Dictionary<string, string> _refreshTokens = new Dictionary<string, string>();

        public JwtTokenService(string secret, string issuer, string audience)
        {
            _secret = secret;
            _issuer = issuer;
            _audience = audience;
        }

        public string GenerateToken(User user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
                new Claim(JwtRegisteredClaimNames.Email, user.Email.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(30), // Token expiration time
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task RevokeToken(string token)
        {
            _refreshTokens.Remove(token);
        }

        public async Task<string> RefreshToken(string token)
        {
            if (_refreshTokens.ContainsKey(token))
            {
                var userId = _refreshTokens[token];
                var user = await GetUserById(Guid.Parse(userId));
                return GenerateToken(user);
            }

            throw new SecurityTokenException("Invalid token.");
        }

        private async Task<User> GetUserById(Guid userId)
        {
            // Fetch the user from the database or repository
            return new User(); // Placeholder
        }
    }
}

--------------------------------------------------------------------------------

// File: MfaService.cs

using Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Security
{
    public class MfaService
    {
        private readonly Dictionary<string, string> _mfaCodes = new Dictionary<string, string>();

        public async Task SendMfaCode(User user)
        {
            var code = GenerateMfaCode();
            _mfaCodes[user.Username] = code;
            // Send the code via email or SMS
        }

        public bool VerifyMfaCode(User user, string code)
        {
            return _mfaCodes.ContainsKey(user.Username) && _mfaCodes[user.Username] == code;
        }

        private string GenerateMfaCode()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString();
        }
    }
}

--------------------------------------------------------------------------------

// File: SecurityService.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.Security
{
    public class SecurityService
    {
        public void EncryptSensitiveData(ref string data)
        {
            data = Convert.ToBase64String(Encoding.UTF8.GetBytes(data));
        }

        public void DecryptSensitiveData(ref string data)
        {
            data = Encoding.UTF8.GetString(Convert.FromBase64String(data)); 
        }

        public void LogSecurityEvent(string eventType, string details)
        {
            Console.WriteLine($"Security Event: {eventType}, Details: {details}"); 
        }

        public void EnforceRateLimiting(string key)
        {
            
        }

        public void DetectAndPreventBruteForce(string key)
        {
            
        }
    }
}

--------------------------------------------------------------------------------

// File: Program.cs

using Application.ApplicationServices;
using Domain.Repositories;
using Domain.DomainServices;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Repositories;
using Infrastructure.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<ITenantRepository, TenantRepository>();
builder.Services.AddScoped<IRoleRepository, RoleRepository>();
builder.Services.AddScoped<UserApplicationService>();
builder.Services.AddScoped<AuthenticationApplicationService>();
builder.Services.AddScoped<AuthenticationService>();
builder.Services.AddScoped<TenantApplicationService>();
builder.Services.AddScoped<TenantApplicationService>();
builder.Services.AddScoped<RoleApplicationService>();
builder.Services.AddScoped<UserProfileApplicationService>();
builder.Services.AddScoped<MfaService>();
builder.Services.AddScoped<SecurityService>();
// Program.cs or Startup.cs

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddMemoryCache();

// Add JWT configuration
var jwtSettings = builder.Configuration.GetSection("Jwt");
var jwtKey = jwtSettings["Key"] ?? throw new InvalidOperationException("JWT Key is missing in configuration.");

builder.Services.AddSingleton(new JwtTokenService(jwtKey, jwtSettings["Issuer"], jwtSettings["Audience"]));

// Add JWT authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

--------------------------------------------------------------------------------

// File: JwtTokenService.cs

using Domain.Entities;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Presentation.Authentication
{
    public class JwtTokenService
    {
        private readonly string _secret;

        public JwtTokenService(string secret)
        {
            _secret = secret;
        }

        public string GenerateToken(User user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Username)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "yourdomain.com",
                audience: "yourdomain.com",
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}


--------------------------------------------------------------------------------

// File: AuthorizationAttribute.cs

using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;

namespace Presentation.Authorization
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
    public class AuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        private readonly string[] _requiredPermissions;

        public AuthorizeAttribute(params string[] requiredPermissions)
        {
            _requiredPermissions = requiredPermissions;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var user = context.HttpContext.User;
            if (!user.Identity.IsAuthenticated)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            var userPermissions = user.Claims.Where(c => c.Type == "permissions").Select(c => c.Value).ToList();
            if (!_requiredPermissions.All(p => userPermissions.Contains(p)))
            {
                context.Result = new ForbidResult();
            }
        }
    }
}


--------------------------------------------------------------------------------

// File: AuthenticationController.cs

using Application.ApplicationServices;
using Application.DTOs;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using LoginRequest = Application.DTOs.LoginRequest;
using RegisterRequest = Application.DTOs.RegisterRequest;

namespace Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly AuthenticationApplicationService _authenticationService;

        public AuthenticationController(AuthenticationApplicationService authenticationService)
        {
            _authenticationService = authenticationService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            try
            {
                var token = await _authenticationService.Login(request.Username, request.Password);
                return Ok(new { Token = token });
            }
            catch (InvalidOperationException ex) when (ex.Message == "MFA code required.")
            {
                return Ok(new { Message = "MFA code required." });
            }
        }

        [HttpPost("verify-mfa")]
        public async Task<IActionResult> VerifyMfa([FromBody] VerifyMfaRequest request)
        {
            var token = await _authenticationService.VerifyMfa(request.Username, request.MfaCode);
            return Ok(new { Token = token });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var token = await _authenticationService.Register(request.Username, request.Email, request.Password);
            return Ok(new { Token = token });
        }

        [HttpPost("revoke-token")]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest request)
        {
            await _authenticationService.RevokeToken(request.Token);
            return Ok();
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var token = await _authenticationService.RefreshToken(request.Token);
            return Ok(new { Token = token });
        }
    }
}

--------------------------------------------------------------------------------

// File: RoleController.cs

using Application.ApplicationServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Application.DTOs;

namespace Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : ControllerBase
    {
        private readonly RoleApplicationService _roleApplicationService;

        public RoleController(RoleApplicationService roleApplicationService)
        {
            _roleApplicationService = roleApplicationService;
        }

        [HttpPost("create")]
        public async Task<IActionResult> Create([FromBody] CreateRoleRequest request)
        {
            await _roleApplicationService.CreateRole(request.TenantId, request.RoleName, request.Permissions);
            return Ok();
        }

        [HttpPut("update")]
        public async Task<IActionResult> Update([FromBody] UpdateRolePermissionsRequest request)
        {
            await _roleApplicationService.UpdateRolePermissions(request.RoleId, request.Permissions);
            return Ok();
        }

        [HttpDelete("delete")]
        public async Task<IActionResult> Delete([FromBody] DeleteRoleRequest request)
        {
            await _roleApplicationService.DeleteRole(request.RoleId);
            return Ok();
        }
    }
}

--------------------------------------------------------------------------------

// File: SecurityEventsController.cs

using Infrastructure.Security;
using Microsoft.AspNetCore.Mvc;
using System;
using Application.DTOs;

namespace Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecurityEventsController : ControllerBase
    {
        private readonly SecurityService _securityService;

        public SecurityEventsController(SecurityService securityService)
        {
            _securityService = securityService;
        }

        [HttpPost("log")]
        public IActionResult LogSecurityEvent([FromBody] SecurityEventRequest request)
        {
            _securityService.LogSecurityEvent(request.EventType, request.Details);
            return Ok();
        }
    }
}

--------------------------------------------------------------------------------

// File: TenantController.cs

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Application.ApplicationServices;
using Application.DTOs;

namespace Presentation.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TenantController : ControllerBase
    {
        private readonly TenantApplicationService _tenantApplicationService;

        public TenantController(TenantApplicationService tenantApplicationService)
        {
            _tenantApplicationService = tenantApplicationService;
        }

        [HttpPost("create")]
        public async Task<IActionResult> Create([FromBody] CreateTenantRequest request)
        {
            await _tenantApplicationService.CreateTenant(request);
            return Ok();
        }

        [HttpPut("update")]
        public async Task<IActionResult> Update([FromBody] UpdateTenantRequest request)
        {
            await _tenantApplicationService.UpdateTenant(request);
            return Ok();
        }

        [HttpDelete("delete")]
        public async Task<IActionResult> Delete([FromBody] DeleteTenantRequest request)
        {
            await _tenantApplicationService.DeleteTenant(request);
            return Ok();
        }
    }
}

--------------------------------------------------------------------------------

// File: UserController.cs

using Application.ApplicationServices;
using Application.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserApplicationService _userApplicationService;

        public UserController(UserApplicationService userApplicationService)
        {
            _userApplicationService = userApplicationService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserRequest request)
        {
            await _userApplicationService.RegisterUser(request);
            return Ok();
        }

        [HttpPost("add-to-tenant")]
        public async Task<IActionResult> AddUserToTenant([FromBody] AddUserToTenantRequest request)
        {
            await _userApplicationService.AddUserToTenant(request);
            return Ok();
        }

        [HttpPost("remove-from-tenant")]
        public async Task<IActionResult> RemoveUserFromTenant([FromBody] RemoveUserFromTenantRequest request)
        {
            await _userApplicationService.RemoveUserFromTenant(request);
            return Ok();
        }
    }
}

--------------------------------------------------------------------------------

// File: UserProfileController.cs

using Application.ApplicationServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Application.DTOs;

namespace Presentation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserProfileController : ControllerBase
    {
        private readonly UserProfileApplicationService _userProfileApplicationService;

        public UserProfileController(UserProfileApplicationService userProfileApplicationService)
        {
            _userProfileApplicationService = userProfileApplicationService;
        }

        [HttpPut("update-profile")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateUserProfileRequest request)
        {
            await _userProfileApplicationService.UpdateUserProfile(request.UserId, request.NewEmail, request.NewUsername);
            return Ok();
        }

        [HttpPut("update-password")]
        public async Task<IActionResult> UpdatePassword([FromBody] UpdatePasswordRequest request)
        {
            await _userProfileApplicationService.UpdatePassword(request.UserId, request.NewPassword);
            return Ok();
        }

        [HttpPut("enable-mfa")]
        public async Task<IActionResult> EnableMfa([FromBody] EnableMfaRequest request)
        {
            await _userProfileApplicationService.EnableMfa(request.UserId, request.SecretKey);
            return Ok();
        }

        [HttpPut("disable-mfa")]
        public async Task<IActionResult> DisableMfa([FromBody] DisableMfaRequest request)
        {
            await _userProfileApplicationService.DisableMfa(request.UserId);
            return Ok();
        }
    }
}

--------------------------------------------------------------------------------

// File: CreateTenantResponse.cs

namespace Presentation.DTOs
{
    public class CreateTenantResponse
    {
        public string TenantId { get; set; }
        public string TenantName { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: RegisterUserResponse.cs

namespace Presentation.DTOs
{
    public class RegisterUserResponse
    {
        public string UserId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: TenantModel.cs

namespace Presentation.Models
{
    public class TenantModel
    {
        public string TenantId { get; set; }
        public string TenantName { get; set; }
        public List<UserModel> Users { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: UserModel.cs

namespace Presentation.Models
{
    public class UserModel
    {
        public string UserId { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public List<TenantModel> Tenants { get; set; }
    }
}


--------------------------------------------------------------------------------

// File: BaseEntity.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharedDomain.Common
{
    public abstract class BaseEntity
    {
        public Guid Id { get;protected set; }

        public DateTime CreatedAt { get;protected set; }
        public DateTime UpdatedAt { get;protected set; }
        protected BaseEntity() { 
            Id= Guid.NewGuid();
        }
        
    }
}


--------------------------------------------------------------------------------

// File: IAggregateRoot.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharedDomain.Common
{
    public interface IAggregateRoot
    {
    }
}


--------------------------------------------------------------------------------

