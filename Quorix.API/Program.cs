using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using VerticalSlice.Models;
using VerticalSlice.Providers;

var builder = WebApplication.CreateBuilder(args);

// Load Configuration
var configuration = builder.Configuration;

// Configure Database Context
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

// Configure Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure Authentication (JWT + OAuth)
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
// JWT Authentication
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:SecretKey"])),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidIssuer = configuration["Jwt:Issuer"],
        ValidAudience = configuration["Jwt:Audience"]
    };
})
// OAuth Authentication
.AddOAuth("OAuth", options =>
{
    options.ClientId = configuration["OAuth:ClientId"];
    options.ClientSecret = configuration["OAuth:ClientSecret"];
    options.CallbackPath = new PathString(configuration["OAuth:CallbackPath"]);
    options.AuthorizationEndpoint = configuration["OAuth:AuthorizationEndpoint"];
    options.TokenEndpoint = configuration["OAuth:TokenEndpoint"];
    options.SaveTokens = true;
    options.EventsType = typeof(ApplicationOAuthEvents);
});

// Register OAuth Event Handler
builder.Services.AddScoped<ApplicationOAuthEvents>();

// Enable CORS (Update allowed origins as needed)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowSpecificOrigins", builder =>
    {
        builder.WithOrigins(configuration["Cors:AllowedOrigins"].Split(","))
               .AllowAnyHeader()
               .AllowAnyMethod()
               .AllowCredentials();
    });
});

// Enable Controllers
builder.Services.AddControllers();

// Enable Swagger (for API documentation & testing)
builder.Services.AddEndpointsApiExplorer();
//builder.Services.AddSwaggerGen();

var app = builder.Build();

// Enable Middleware
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    //app.UseSwagger();
    //app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseRouting();

// Apply CORS Policy
app.UseCors("AllowSpecificOrigins");

// Apply Authentication & Authorization
app.UseAuthentication();
app.UseAuthorization();

// Map Controllers
app.MapControllers();

// Start Application
app.Run();
