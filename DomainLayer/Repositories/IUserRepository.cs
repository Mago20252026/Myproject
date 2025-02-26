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