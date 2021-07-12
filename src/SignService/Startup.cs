using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.AspNetCore;
using Microsoft.ApplicationInsights.AspNetCore.TelemetryInitializers;
using Microsoft.ApplicationInsights.Channel;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.ApplicationInsights.SnapshotCollector;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Newtonsoft.Json;
using SignService.Authentication;
using SignService.Services;
using SignService.SigningTools;
using SignService.Utils;

namespace SignService
{
    public class Startup
    {
        readonly IWebHostEnvironment environment;
        readonly string contentPath;
        public static string ManifestLocation { get; private set; }
        public Startup(IWebHostEnvironment env, IConfiguration configuration)
        {
            environment = env;
            Configuration = configuration;

            contentPath = env.ContentRootPath;
            // If we're running on Azure App Services, we have to invoke from the underlying
            // location due to CSRSS/registration-free COM manifest issues

            // running on azure
            if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("REGION_NAME")))
            {
                var home = Environment.GetEnvironmentVariable("HOME_EXPANDED");
                if (!string.IsNullOrWhiteSpace(home))
                {
                    contentPath = $@"{home}\site\wwwroot";
                }
            }

            var is64bit = IntPtr.Size == 8;
            var basePath = Path.Combine(contentPath, $"tools\\SDK\\{(is64bit ? "x64" : "x86")}");
            ManifestLocation = Path.Combine(contentPath, "tools", "SDK", is64bit ? "x64" : "x86", "SignTool.exe.manifest");

            //
            // Ensure we invoke wintrust!DllMain before we get too far.
            // This will call wintrust!RegisterSipsFromIniFile and read in wintrust.dll.ini
            // to swap out some local SIPs. Internally, wintrust will call LoadLibraryW
            // on each DLL= entry, so we need to also adjust our DLL search path or we'll
            // load unwanted system-provided copies.
            //
            Kernel32.SetDllDirectoryW(basePath);
            Kernel32.LoadLibraryW($@"{basePath}\wintrust.dll");
            Kernel32.LoadLibraryW($@"{basePath}\mssign32.dll");
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Configure SnapshotCollector from application settings
            services.Configure<SnapshotCollectorConfiguration>(Configuration.GetSection(nameof(SnapshotCollectorConfiguration)));
            services.AddApplicationInsightsTelemetry();

            // Add SnapshotCollector telemetry processor.
            services.AddSingleton<ITelemetryProcessorFactory>(sp => new SnapshotCollectorTelemetryProcessorFactory(sp));
            services.AddSingleton<ITelemetryInitializer, VersionTelemetry>();
            services.AddSingleton<ITelemetryInitializer, UserTelemetry>();

            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            // Add framework services.
            var b = services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
              .AddMicrosoftIdentityWebApp(Configuration);

            b
                  .EnableTokenAcquisitionToCallDownstreamApi(new[] { "https://graph.windows.net/.default" })
                     // .AddMicrosoftGraph(Configuration.GetSection("DownstreamApi"))
                      .AddInMemoryTokenCaches();


            services.AddAuthentication()
          .AddMicrosoftIdentityWebApi(Configuration,
                                      JwtBearerDefaults.AuthenticationScheme)
          .EnableTokenAcquisitionToCallDownstreamApi();


            //services.AddAuthentication(AzureADDefaults.AuthenticationScheme)
            //        .AddAzureAD(options => Configuration.Bind("AzureAd", options))
            //        .AddAzureADBearer(options => Configuration.Bind("AzureAd", options));

            services.Configure<CookieAuthenticationOptions>(OpenIdConnectDefaults.AuthenticationScheme, options => options.Events = new CookieAuthenticationEventsHandler());

            services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                options.TokenValidationParameters.RoleClaimType = "roles";
                options.TokenValidationParameters.NameClaimType = "name";
            });

            services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
            {
                options.Audience = Configuration["AzureAd:Audience"];
                options.TokenValidationParameters.RoleClaimType = "roles";
                options.TokenValidationParameters.NameClaimType = "name";

                // TODO: This has to be hooked up differently
                options.Events = new JwtBearerEventsHandler(); 
            });

            services.AddSession();

            services.Configure<ResourceIds>(Configuration.GetSection("Resources"));
            services.Configure<AdminConfig>(Configuration.GetSection("Admin"));
            services.Configure<WindowsSdkFiles>(ConfigureWindowsSdkFiles);

            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddScoped<ITelemetryLogger, TelemetryLogger>();
            services.AddSingleton<IApplicationConfiguration, ApplicationConfiguration>();
            services.AddSingleton<IDirectoryUtility, DirectoryUtility>();

            // Add in our User wrapper
            services.AddScoped<IUser, HttpContextUser>();

            // The Key Vault Service must be scoped as the context is per user in the request
            services.AddScoped<IKeyVaultService, KeyVaultService>();

            // Admin service contains per-user context
            services.AddScoped<IUserAdminService, UserAdminService>();
            services.AddScoped<IGraphHttpService, GraphHttpService>();
            services.AddScoped<IKeyVaultAdminService, KeyVaultAdminService>();

            // Code signing tools contain per-user/request data
            services.AddScoped<IAppxFileFactory, AppxFileFactory>();
            services.AddScoped<ICodeSignService, AzureSignToolSignService>();
            services.AddScoped<ICodeSignService, VsixSignService>();
            services.AddScoped<ICodeSignService, MageSignService>();
            services.AddScoped<ICodeSignService, AppInstallerService>();
            services.AddScoped<ICodeSignService, NuGetSignService>();

            services.AddScoped<ISigningToolAggregate, SigningToolAggregate>();

            services.AddScoped<IFileNameService, FileNameService>();

            services.AddControllersWithViews(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            }).AddMicrosoftIdentityUI();
            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app,
                              IWebHostEnvironment env,
                              IApplicationConfiguration applicationConfiguration)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }

            // Retreive application specific config from Azure AD
            applicationConfiguration.InitializeAsync().Wait();

            JsonSerializerSettings jsonSettingsProvider()
            {
                var settings = new JsonSerializerSettings
                {
                    ContractResolver = new CoreContractResolver(app.ApplicationServices),
                };
                return settings;
            }

            JsonConvert.DefaultSettings = jsonSettingsProvider;

            // This is here because we need to P/Invoke into clr.dll for _AxlPublicKeyBlobToPublicKeyToken 
            var is64bit = IntPtr.Size == 8;
            var windir = Environment.GetEnvironmentVariable("windir");
            var fxDir = is64bit ? "Framework64" : "Framework";
            var netfxDir = $@"{windir}\Microsoft.NET\{fxDir}\v4.0.30319";
            AddEnvironmentPaths(new[] { netfxDir });
            

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseSession();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }

        static void AddEnvironmentPaths(IEnumerable<string> paths)
        {
            var path = new[] { Environment.GetEnvironmentVariable("PATH") ?? string.Empty };
            var newPath = string.Join(Path.PathSeparator.ToString(), path.Concat(paths));
            Environment.SetEnvironmentVariable("PATH", newPath);
        }

        void ConfigureWindowsSdkFiles(WindowsSdkFiles options)
        {
            var is64bit = IntPtr.Size == 8;
            var basePath = Path.Combine(contentPath, $"tools\\SDK\\{(is64bit ? "x64" : "x86")}");
            options.MakeAppxPath = Path.Combine(basePath, "makeappx.exe");
        }

        class SnapshotCollectorTelemetryProcessorFactory : ITelemetryProcessorFactory
        {
            readonly IServiceProvider serviceProvider;

            public SnapshotCollectorTelemetryProcessorFactory(IServiceProvider serviceProvider) =>
                this.serviceProvider = serviceProvider;

            public ITelemetryProcessor Create(ITelemetryProcessor next)
            {
                var snapshotConfigurationOptions = serviceProvider.GetService<IOptions<SnapshotCollectorConfiguration>>();
                return new SnapshotCollectorTelemetryProcessor(next, configuration: snapshotConfigurationOptions.Value);
            }
        }

        class VersionTelemetry : ITelemetryInitializer
        {
            public void Initialize(ITelemetry telemetry)
            {
                telemetry.Context.Component.Version = Program.AssemblyInformationalVersion;
            }
        }

        class UserTelemetry : TelemetryInitializerBase
        {
            public UserTelemetry(IHttpContextAccessor httpContextAccessor) : base(httpContextAccessor)
            {                
            }

            protected override void OnInitializeTelemetry(HttpContext httpContext, RequestTelemetry requestTelemetry, ITelemetry telemetry)
            {
                if (httpContext.RequestServices == null)
                    return;

                var identity =  httpContext.User.Identity;
                if (!identity.IsAuthenticated)
                    return;


                var upn = ((ClaimsIdentity)identity).FindFirst("upn")?.Value;
                if (upn != null)
                    telemetry.Context.User.AuthenticatedUserId = upn;

                var userId = ((ClaimsIdentity)identity).FindFirst("oid")?.Value;

                if (userId == null)
                    return;

                telemetry.Context.User.Id = userId;
                telemetry.Context.User.AccountId = userId;
            }
        }

    }
}
