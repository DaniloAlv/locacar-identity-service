using LocacaoDeCarros.Identity.API.Data;
using LocacaoDeCarros.Identity.API.Models;
using Microsoft.EntityFrameworkCore;

namespace LocacaoDeCarros.Identity.API.Repositories
{
    public interface IRefreshTokenRepository
    {
        Task CreateRefreshToken(RefreshToken refreshToken);
        void RemoveRefreshToken(string email);
        Task<RefreshToken> GetRefreshToken(Guid token);
        Task<bool> SaveRefreshTokenChanges();
    }

    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly IdentityContext _context;

        public RefreshTokenRepository(IdentityContext context)
        {
            _context = context;
        }

        public async Task<RefreshToken> GetRefreshToken(Guid token)
        {
            return await _context.RefreshTokens
                .AsNoTracking()
                .FirstOrDefaultAsync(rt => rt.Token == token);
        }

        public async Task CreateRefreshToken(RefreshToken refreshToken)
        {
            await _context.AddAsync(refreshToken);
        }

        public void RemoveRefreshToken(string email)
        {
            var refreshTokens = _context.RefreshTokens
                .AsNoTracking()
                .Where(rt => rt.UserEmail == email);

            _context.RefreshTokens.RemoveRange(refreshTokens);
        }

        public async Task<bool> SaveRefreshTokenChanges()
        {
            return await _context.SaveChangesAsync() > 0;
        }
    }
}
