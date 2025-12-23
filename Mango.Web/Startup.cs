using Mango.Web.Services;
using Mango.Web.Services.IServices;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Net.Http; // Required for HttpClient

namespace Mango.Web
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddHttpClient<IProductService, ProductService>();
            services.AddHttpClient<ICartService, CartService>();
            services.AddHttpClient<ICouponService, CouponService>();

            SD.ProductAPIBase = Configuration["ServiceUrls:ProductAPI"];
            SD.ShoppingCartAPIBase = Configuration["ServiceUrls:ShoppingCartAPI"];
            SD.CouponAPIBase = Configuration["ServiceUrls:CouponAPI"];

            services.AddScoped<IProductService, ProductService>();
            services.AddScoped<ICartService, CartService>();
            services.AddScoped<ICouponService, CouponService>();
            services.AddControllersWithViews();

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "Cookies";
                options.DefaultChallengeScheme = "oidc";
            })
            .AddCookie("Cookies", c => c.ExpireTimeSpan = TimeSpan.FromMinutes(10))
            .AddOpenIdConnect("oidc", options =>
            {
                // 1. Basic Info
                options.Authority = "https://localhost:7001";
                options.ClientId = "mango";
                options.ClientSecret = "secret";
                options.ResponseType = "code";

                // 2. SSL BYPASS (The Bridge)
                // We create a handler that ignores SSL errors
                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                };

                // We tell the Token Exchange to use this handler
                options.BackchannelHttpHandler = handler;

                // We tell the Discovery (Finding URLs) to use this handler
                // THIS FIXES "Invalid Request URI" without breaking Keys
                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    "https://localhost:7001/.well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever(new HttpClient(handler)) { RequireHttps = false }
                );

                // 3. ESSENTIAL .NET 8 SETTINGS
                options.SignInScheme = "Cookies";
                options.SaveTokens = true; // Fixes the "Missing Token" error

                // This is crucial for migrating from .NET 6 to 8
                options.UseSecurityTokenValidator = true;

                // 4. SCOPES
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("mango");

                // 5. STANDARD VALIDATION (No Manual Hacks)
                // We let .NET handle the validation naturally now that the connection works.
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };

                options.Events = new Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectEvents
                {
                    OnRemoteFailure = context =>
                    {
                        // If the error is "Access Denied" (User clicked Cancel), or any other error
                        // We just redirect them to the Home page instead of crashing.
                        context.Response.Redirect("/");
                        context.HandleResponse();
                        return System.Threading.Tasks.Task.CompletedTask;
                    }
                };
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}