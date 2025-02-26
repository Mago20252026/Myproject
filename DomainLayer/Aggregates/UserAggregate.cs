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
