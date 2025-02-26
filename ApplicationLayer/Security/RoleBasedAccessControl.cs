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
