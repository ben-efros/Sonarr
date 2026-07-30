using FluentValidation;
using FluentValidation.TestHelper;
using Moq;
using NUnit.Framework;
using NzbDrone.Common.Disk;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;
using NzbDrone.Core.Security;
using NzbDrone.Core.Update;
using Sonarr.Api.V3.Config;

namespace NzbDrone.Api.Test.v3.Config
{
    [TestFixture]
    public class HostConfigControllerFixture
    {
        private TestHostConfigController _controller;

        [SetUp]
        public void Setup()
        {
            var configFileProvider = new Mock<IConfigFileProvider>();
            var configService = new Mock<IConfigService>();
            var userService = new Mock<IUserService>();
            var diskProvider = new Mock<IDiskProvider>();

            _controller = new TestHostConfigController(configFileProvider.Object, configService.Object, userService.Object, diskProvider.Object);
        }

        private static HostConfigResource ValidResource()
        {
            return new HostConfigResource
            {
                BindAddress = "*",
                Port = 8989,
                UrlBase = string.Empty,
                InstanceName = "Sonarr",
                AuthenticationMethod = AuthenticationType.None,
                AuthenticationRequired = AuthenticationRequiredType.Enabled,
                Password = string.Empty,
                PasswordConfirmation = string.Empty,
                EnableSsl = false,
                LogSizeLimit = 1,
                Branch = "main",
                UpdateMechanism = UpdateMechanism.BuiltIn,
                BackupFolder = "Backups",
                BackupInterval = 7,
                BackupRetention = 28,
                XForwardedForTrustLevel = XForwardedForTrustLevel.Disabled,
                TrustedProxyCidrs = string.Empty,
                AuthenticationRequiredCidrs = string.Empty
            };
        }

        [TestCase("10.0.0.0/8")]
        [TestCase("192.168.1.10/32")]
        [TestCase("::1/128")]
        [TestCase("fc00::/7")]
        [TestCase("10.0.0.0/8,192.168.1.0/24")]
        [TestCase("10.0.0.0/8, 192.168.1.0/24, fc00::/7")]
        [TestCase("10.0.0.0/8\n192.168.1.0/24")]
        public void should_accept_valid_trusted_proxy_cidrs_when_custom_trust_level(string cidrs)
        {
            var resource = ValidResource();
            resource.XForwardedForTrustLevel = XForwardedForTrustLevel.Custom;
            resource.TrustedProxyCidrs = cidrs;

            var result = _controller.Validator.TestValidate(resource);

            result.ShouldNotHaveValidationErrorFor(r => r.TrustedProxyCidrs);
        }

        [TestCase("")]
        [TestCase(" ")]
        [TestCase("not-a-cidr")]
        [TestCase("10.0.0.0")]
        [TestCase("10.0.0.0/33")]
        [TestCase("10.0.0.0/-1")]
        [TestCase("256.256.256.256/24")]
        [TestCase("fe80::/129")]
        [TestCase("10.0.0.0/8,not-a-cidr")]
        public void should_reject_invalid_trusted_proxy_cidrs_when_custom_trust_level(string cidrs)
        {
            var resource = ValidResource();
            resource.XForwardedForTrustLevel = XForwardedForTrustLevel.Custom;
            resource.TrustedProxyCidrs = cidrs;

            var result = _controller.Validator.TestValidate(resource);

            result.ShouldHaveValidationErrorFor(r => r.TrustedProxyCidrs);
        }

        [TestCase(XForwardedForTrustLevel.Disabled)]
        [TestCase(XForwardedForTrustLevel.Rfc1918)]
        public void should_not_validate_trusted_proxy_cidrs_when_trust_level_is_not_custom(XForwardedForTrustLevel trustLevel)
        {
            var resource = ValidResource();
            resource.XForwardedForTrustLevel = trustLevel;
            resource.TrustedProxyCidrs = "not-a-cidr";

            var result = _controller.Validator.TestValidate(resource);

            result.ShouldNotHaveValidationErrorFor(r => r.TrustedProxyCidrs);
        }

        [TestCase("10.0.0.0/8")]
        [TestCase("192.168.1.10/32")]
        [TestCase("10.0.0.0/8,192.168.1.0/24,fc00::/7")]
        public void should_accept_valid_authentication_required_cidrs_when_custom_addresses(string cidrs)
        {
            var resource = ValidResource();
            resource.AuthenticationRequired = AuthenticationRequiredType.DisabledForCustomAddresses;
            resource.AuthenticationRequiredCidrs = cidrs;

            var result = _controller.Validator.TestValidate(resource);

            result.ShouldNotHaveValidationErrorFor(r => r.AuthenticationRequiredCidrs);
        }

        [TestCase("")]
        [TestCase("not-a-cidr")]
        [TestCase("10.0.0.0/33")]
        [TestCase("10.0.0.0/8,garbage")]
        public void should_reject_invalid_authentication_required_cidrs_when_custom_addresses(string cidrs)
        {
            var resource = ValidResource();
            resource.AuthenticationRequired = AuthenticationRequiredType.DisabledForCustomAddresses;
            resource.AuthenticationRequiredCidrs = cidrs;

            var result = _controller.Validator.TestValidate(resource);

            result.ShouldHaveValidationErrorFor(r => r.AuthenticationRequiredCidrs);
        }

        [TestCase(AuthenticationRequiredType.Enabled)]
        [TestCase(AuthenticationRequiredType.Disabled)]
        [TestCase(AuthenticationRequiredType.DisabledForLocalhost)]
        [TestCase(AuthenticationRequiredType.DisabledForLocalAddresses)]
        public void should_not_validate_authentication_required_cidrs_when_not_custom_addresses(AuthenticationRequiredType authRequired)
        {
            var resource = ValidResource();
            resource.AuthenticationRequired = authRequired;
            resource.AuthenticationRequiredCidrs = "not-a-cidr";

            var result = _controller.Validator.TestValidate(resource);

            result.ShouldNotHaveValidationErrorFor(r => r.AuthenticationRequiredCidrs);
        }

        // Exposes the protected SharedValidator (built up from FluentValidation
        // rules registered in the HostConfigController constructor) so its
        // CIDR-list rules can be exercised directly with FluentValidation's
        // TestValidate helper, without needing a live HTTP pipeline.
        private class TestHostConfigController : HostConfigController
        {
            public TestHostConfigController(
                IConfigFileProvider configFileProvider,
                IConfigService configService,
                IUserService userService,
                IDiskProvider diskProvider)
                : base(configFileProvider, configService, userService, diskProvider)
            {
            }

            public IValidator<HostConfigResource> Validator => SharedValidator;
        }
    }
}
