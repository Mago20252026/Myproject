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