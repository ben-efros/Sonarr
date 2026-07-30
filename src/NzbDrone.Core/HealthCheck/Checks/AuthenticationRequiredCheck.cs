using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;
using NzbDrone.Core.Configuration.Events;
using NzbDrone.Core.Lifecycle;
using NzbDrone.Core.Localization;

namespace NzbDrone.Core.HealthCheck.Checks
{
    [CheckOn(typeof(ApplicationStartedEvent))]
    [CheckOn(typeof(ConfigSavedEvent))]
    public class AuthenticationRequiredCheck : HealthCheckBase
    {
        private readonly IConfigFileProvider _configFileProvider;

        public AuthenticationRequiredCheck(IConfigFileProvider configFileProvider, ILocalizationService localizationService)
            : base(localizationService)
        {
            _configFileProvider = configFileProvider;
        }

        public override HealthCheck Check()
        {
            var authenticationRequired = _configFileProvider.AuthenticationRequired;

            if (authenticationRequired == AuthenticationRequiredType.Disabled)
            {
                return new HealthCheck(GetType(),
                    HealthCheckResult.Warning,
                    _localizationService.GetLocalizedString("AuthenticationRequiredDisabledHealthCheckMessage"),
                    "#authentication-is-disabled");
            }

            if (authenticationRequired == AuthenticationRequiredType.DisabledForLocalAddresses)
            {
                return new HealthCheck(GetType(),
                    HealthCheckResult.Warning,
                    _localizationService.GetLocalizedString("AuthenticationRequiredDisabledForLocalAddressesHealthCheckMessage"),
                    "#authentication-is-disabled");
            }

            if (authenticationRequired == AuthenticationRequiredType.DisabledForCustomAddresses)
            {
                return new HealthCheck(GetType(),
                    HealthCheckResult.Warning,
                    _localizationService.GetLocalizedString("AuthenticationRequiredDisabledForCustomAddressesHealthCheckMessage"),
                    "#authentication-is-disabled");
            }

            return new HealthCheck(GetType());
        }
    }
}
