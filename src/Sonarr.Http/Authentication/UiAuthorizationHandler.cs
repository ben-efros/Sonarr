using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using NzbDrone.Common.Extensions;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;
using NzbDrone.Core.Configuration.Events;
using NzbDrone.Core.Messaging.Events;
using Sonarr.Http.Extensions;

namespace NzbDrone.Http.Authentication
{
    public class UiAuthorizationHandler : AuthorizationHandler<BypassableDenyAnonymousAuthorizationRequirement>, IAuthorizationRequirement, IHandle<ConfigSavedEvent>
    {
        private readonly IConfigFileProvider _configService;
        private AuthenticationRequiredType _authenticationRequired;

        public UiAuthorizationHandler(IConfigFileProvider configService)
        {
            _configService = configService;
            _authenticationRequired = configService.AuthenticationRequired;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, BypassableDenyAnonymousAuthorizationRequirement requirement)
        {
            switch (_authenticationRequired)
            {
                case AuthenticationRequiredType.Enabled:
                    // Authentication is always required; nothing bypasses it.
                    break;

                case AuthenticationRequiredType.Disabled:
                    // Authentication is never required, regardless of the
                    // requesting address. This is the most permissive option
                    // and is equivalent to setting AuthenticationMethod to
                    // None, but expressed as its own explicit choice.
                    context.Succeed(requirement);
                    break;

                case AuthenticationRequiredType.DisabledForLocalhost:
                    if (TryGetRemoteAddress(context, out var loopbackAddress) && IPAddress.IsLoopback(loopbackAddress))
                    {
                        context.Succeed(requirement);
                    }

                    break;

                case AuthenticationRequiredType.DisabledForLocalAddresses:
                    if (TryGetRemoteAddress(context, out var localAddress) &&
                        (localAddress.IsLocalAddress() ||
                         (_configService.TrustCgnatIpAddresses && localAddress.IsCgnatIpAddress())))
                    {
                        context.Succeed(requirement);
                    }

                    break;

                case AuthenticationRequiredType.DisabledForCustomAddresses:
                    if (TryGetRemoteAddress(context, out var customAddress) &&
                        CidrUtils.IsAddressInAnyCidr(customAddress, _configService.AuthenticationRequiredCidrs))
                    {
                        context.Succeed(requirement);
                    }

                    break;
            }

            return Task.CompletedTask;
        }

        private static bool TryGetRemoteAddress(AuthorizationHandlerContext context, out IPAddress address)
        {
            address = null;

            return context.Resource is HttpContext httpContext &&
                   IPAddress.TryParse(httpContext.GetRemoteIP(), out address);
        }

        public void Handle(ConfigSavedEvent message)
        {
            _authenticationRequired = _configService.AuthenticationRequired;
        }
    }
}
