using EclipsVault.Core.Domain.Enums;
using EclipsVault.Infrastructure.Auditing;
using EclipsVault.Infrastructure.Caching;
using EclipsVault.Infrastructure.Distributed;
using EclipsVault.Infrastructure.Media;
using EclipsVault.Infrastructure.Notifications;
using EclipsVault.Infrastructure.Persistence;
using EclipsVault.Infrastructure.Persistence.Interceptors;
using EclipsVault.Infrastructure.Persistence.Repositories;
using EclipsVault.Infrastructure.Security;
using EclipsVault.Infrastructure.Security.WebAuthn;
using EclipsVault.Infrastructure.Workers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace EclipsVault.Infrastructure;

/// <summary>Registers every Infrastructure implementation behind its Core interface.</summary>
public static class DependencyInjection
{
    public static IServiceCollection AddEclipsVaultInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<CryptoOptions>(configuration.GetSection(CryptoOptions.SectionName));
        services.Configure<Argon2Options>(configuration.GetSection(Argon2Options.SectionName));
        services.Configure<CacheOptions>(configuration.GetSection(CacheOptions.SectionName));
        services.Configure<LifecycleOptions>(configuration.GetSection(LifecycleOptions.SectionName));
        services.Configure<WebAuthnOptions>(configuration.GetSection(WebAuthnOptions.SectionName));
        services.Configure<EmailOptions>(configuration.GetSection(EmailOptions.SectionName));
        services.Configure<AuditSigningOptions>(configuration.GetSection(AuditSigningOptions.SectionName));

        services.TryAddSingleton(TimeProvider.System);
        services.AddMemoryCache();

        // Brute-force lockout thresholds (Core policy record, bound from configuration).
        var lockout = configuration.GetSection("Lockout");
        services.AddSingleton(new LockoutPolicy(
            lockout.GetValue<int?>("MaxFailedAttempts") ?? LockoutPolicy.Default.MaxFailedAttempts,
            TimeSpan.FromMinutes(lockout.GetValue<int?>("LockoutMinutes") ?? LockoutPolicy.Default.LockoutDuration.TotalMinutes)));

        // Step-up re-authentication policy (Core options, bound from configuration).
        var stepUp = configuration.GetSection(StepUpOptions.SectionName);
        services.AddSingleton(new StepUpOptions
        {
            MinimumSensitivity = stepUp.GetValue<SensitivityLevel?>("MinimumSensitivity") ?? new StepUpOptions().MinimumSensitivity,
            MaxAuthAgeMinutes = stepUp.GetValue<int?>("MaxAuthAgeMinutes") ?? new StepUpOptions().MaxAuthAgeMinutes
        });
        services.AddScoped<IStepUpService, StepUpService>();

        // Email domain used when auto-generating account emails.
        services.AddSingleton(new UserDirectoryOptions(
            configuration.GetValue<string?>("Identity:EmailDomain") ?? UserDirectoryOptions.Default.EmailDomain));

        // Persistence — the audit interceptor rides inside every SaveChanges, stamping each
        // audit row into the tamper-evidence hash chain (one shared, serialized chain head).
        services.AddSingleton<AuditChain>();
        services.AddScoped<AuditSaveChangesInterceptor>();

        // The connection string is deliberately absent from appsettings.json so credentials
        // are never committed. It must be supplied by the environment (ConnectionStrings__DefaultConnection)
        // or a secret store; the local dev value lives in appsettings.Development.json.
        var connectionString = configuration.GetConnectionString("DefaultConnection")
            ?? throw new InvalidOperationException(
                "Database connection string 'DefaultConnection' is not configured. Set the " +
                "ConnectionStrings__DefaultConnection environment variable (or a secret store).");

        services.AddDbContext<EclipsVaultDbContext>((sp, options) => options
            .UseSqlServer(connectionString)
            .AddInterceptors(sp.GetRequiredService<AuditSaveChangesInterceptor>()));

        // The one place audit rows are written (fail-closed).
        services.AddScoped<IAuditSink, AuditSink>();

        services.AddScoped<ISecretRepository, SecretRepository>();
        services.AddScoped<ISecretGrantRepository, SecretGrantRepository>();
        services.AddScoped<IServiceAccountRepository, ServiceAccountRepository>();
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<IPasskeyCredentialRepository, PasskeyCredentialRepository>();
        services.AddScoped<IMfaRecoveryCodeRepository, MfaRecoveryCodeRepository>();
        services.AddScoped<IAccessRequestRepository, AccessRequestRepository>();
        services.AddScoped<IEmailLogRepository, EmailLogRepository>();

        // Security primitives.
        services.AddSingleton<IPasswordHasher, Argon2idPasswordHasher>();
        services.AddSingleton<IBreachedPasswordScreen, BundledBreachedPasswordScreen>();
        services.AddSingleton<ITotpService, TotpService>();
        services.AddSingleton<IAvatarProcessor, ImageSharpAvatarProcessor>();
        services.AddSingleton<IApiKeyFactory, ApiKeyFactory>();
        services.AddSingleton<IKekProvider, EnvironmentKekProvider>();
        services.AddSingleton<AesGcmCryptoEngine>();
        // Opt-in KMS engine: constructed lazily (and only reaches Vault) when Crypto:Engine=VaultTransit.
        services.Configure<VaultOptions>(configuration.GetSection(VaultOptions.SectionName));
        services.AddSingleton(sp => new VaultTransitCryptoEngine(new HttpClient(), sp.GetRequiredService<IOptions<VaultOptions>>()));
        services.AddSingleton<ICryptoEngineFactory, CryptoEngineFactory>();
        services.AddScoped<IKekRotationService, KekRotationService>();

        // Resilience & active defence. Session revocation, the intrusion IP blacklist, and the
        // encrypted-envelope cache all hold shared runtime state. Back them with Redis when it is
        // configured — mandatory for multi-node scale-out so a revocation or block on one node is
        // honoured by every node — or with the in-process stores for a zero-infrastructure single node.
        services.Configure<RedisOptions>(configuration.GetSection(RedisOptions.SectionName));
        var redisOptions = configuration.GetSection(RedisOptions.SectionName).Get<RedisOptions>() ?? new RedisOptions();
        if (redisOptions.Enabled)
        {
            // One multiplexer per process (the expensive, thread-safe singleton). Connecting here
            // fails fast at startup if the shared store is unreachable — it now holds security state.
            services.AddSingleton<IConnectionMultiplexer>(ConnectionMultiplexer.Connect(redisOptions.Configuration));
            services.AddSingleton<ISecretCache, RedisSecretCache>();
            services.AddSingleton<IIpBlacklist, RedisIpBlacklist>();
            services.AddSingleton<ISessionRevocationService, RedisSessionRevocationService>();
            services.AddSingleton<ISessionRegistry, RedisSessionRegistry>();
        }
        else
        {
            services.AddSingleton<ISecretCache, MemorySecretCache>();
            services.AddSingleton<IIpBlacklist, InMemoryIpBlacklist>();
            services.AddSingleton<ISessionRevocationService, InMemorySessionRevocationService>();
            services.AddSingleton<ISessionRegistry, InMemorySessionRegistry>();
        }
        services.AddScoped<IIntrusionResponseService, IntrusionResponseService>();

        // Runtime-managed trusted networks + audit reading.
        services.AddScoped<ITrustedNetworkService, TrustedNetworkService>();
        services.AddScoped<IAuditLogReader, AuditLogReader>();

        // Audit attestation: an ECDSA signer over the hash-chain head + the export service.
        services.AddSingleton<IAuditCheckpointSigner, EcdsaAuditCheckpointSigner>();
        services.AddScoped<IAuditCheckpointService, AuditCheckpointService>();

        // Application services (pure Core classes, composed here).
        services.AddScoped<ISecretService, SecretService>();
        services.AddScoped<ISecretGrantService, SecretGrantService>();
        services.AddScoped<IAccessRequestService, AccessRequestService>();
        services.AddScoped<ServiceAccountService>();
        services.AddScoped<IServiceAccountService>(sp => sp.GetRequiredService<ServiceAccountService>());
        services.AddScoped<IApiKeyAuthenticator>(sp => sp.GetRequiredService<ServiceAccountService>());
        services.AddScoped<IVaultAuthenticationService, VaultAuthenticationService>();
        services.AddScoped<IUserAdminService, UserAdminService>();
        services.AddScoped<IProfileService, ProfileService>();
        services.AddScoped<IMfaRecoveryService, MfaRecoveryService>();
        services.AddScoped<IDashboardService, DashboardService>();
        services.AddScoped<IActivityService, ActivityService>();
        services.AddScoped<ISignInHistoryService, SignInHistoryService>();
        services.AddScoped<ISecurityCheckupService, SecurityCheckupService>();
        services.AddScoped<IPersonalDataExportService, PersonalDataExportService>();
        services.AddScoped<IPasskeyService, PasskeyService>();

        // Notifications: pick the email transport by config, mirror Email:Enabled into the
        // Core policy record, and compose/record through the notification service.
        services.AddSingleton(new NotificationOptions(
            configuration.GetValue<bool?>("Email:Enabled") ?? NotificationOptions.Default.Enabled));
        if (string.Equals(configuration.GetValue<string>("Email:Sender"), "Smtp", StringComparison.OrdinalIgnoreCase))
        {
            services.AddSingleton<IEmailSender, SmtpEmailSender>();
        }
        else
        {
            services.AddSingleton<IEmailSender, LoggingEmailSender>();
        }
        services.AddScoped<INotificationService, NotificationService>();

        return services;
    }
}
