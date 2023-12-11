using LocacaoDeCarros.Identity.API.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using NetDevPack.Security.Jwt.Core.Model;
using NetDevPack.Security.Jwt.Store.EntityFrameworkCore;

namespace LocacaoDeCarros.Identity.API.Data
{
    public class IdentityContext : IdentityDbContext, ISecurityKeyContext
    {
        public IdentityContext(DbContextOptions options) : base(options) { }

        public DbSet<KeyMaterial> SecurityKeys { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}
