using Amazon.DynamoDBv2;
using LocacaoDeCarros.Identity.API.Data;
using LocacaoDeCarros.Identity.API.Models;
using LocacaoDeCarros.Identity.API.Repositories;
using LocacaoDeCarros.Identity.API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NetDevPack.Security.Jwt.AspNetCore;
using NetDevPack.Security.Jwt.Core;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Configuration.AddUserSecrets<Program>();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<IdentityContext>(opt =>
{
    opt.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddIdentity<IdentityUser, IdentityRole>(opt =>
{
    opt.Password.RequiredLength = 8;
    opt.Password.RequireDigit = true; 
    opt.Password.RequireNonAlphanumeric = true;
    opt.Password.RequireUppercase = true;

    opt.User.RequireUniqueEmail = true;
})
    .AddEntityFrameworkStores<IdentityContext>()
    .AddDefaultTokenProviders();

builder.Services.AddScoped<IIdentityService, IdentityService>();

builder.Services.AddSingleton<IRefreshTokenRepository, RefreshTokenRepository>();

var configToken = builder.Configuration.GetSection("TokenAppSettings");
builder.Services.Configure<TokenAppSettings>(configToken);
var tokenSettings = configToken.Get<TokenAppSettings>();

builder.Services.AddJwksManager().UseJwtValidation();

builder.Services.AddAuthorization();

builder.Services.AddAuthentication(auth =>
{
    auth.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    auth.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(bearer =>
    {
        bearer.SaveToken = true;
        bearer.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidAudiences = tokenSettings.Audiences, 
            ValidIssuer = tokenSettings.Issuer, 
            ValidateIssuer = true, 
            ValidateAudience = true, 
            ValidateLifetime = true, 
            ValidateIssuerSigningKey = true
        };
    });

builder.Services.AddMemoryCache();

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

app.UseEndpoints(endpoint =>
{
    endpoint.MapControllers();
});

app.UseJwksDiscovery();

app.Run();
