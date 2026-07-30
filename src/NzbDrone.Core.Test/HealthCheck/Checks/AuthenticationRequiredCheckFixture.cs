using Moq;
using NUnit.Framework;
using NzbDrone.Core.Authentication;
using NzbDrone.Core.Configuration;
using NzbDrone.Core.HealthCheck.Checks;
using NzbDrone.Core.Localization;
using NzbDrone.Core.Test.Framework;

namespace NzbDrone.Core.Test.HealthCheck.Checks
{
    [TestFixture]
    public class AuthenticationRequiredCheckFixture : CoreTest<AuthenticationRequiredCheck>
    {
        [SetUp]
        public void Setup()
        {
            Mocker.GetMock<ILocalizationService>()
                  .Setup(s => s.GetLocalizedString(It.IsAny<string>()))
                  .Returns("Some Warning Message");
        }

        private void GivenAuthenticationRequired(AuthenticationRequiredType authenticationRequired)
        {
            Mocker.GetMock<IConfigFileProvider>()
                  .SetupGet(s => s.AuthenticationRequired)
                  .Returns(authenticationRequired);
        }

        [Test]
        public void should_return_ok_when_enabled()
        {
            GivenAuthenticationRequired(AuthenticationRequiredType.Enabled);

            Subject.Check().ShouldBeOk();
        }

        [Test]
        public void should_return_ok_when_disabled_for_localhost()
        {
            GivenAuthenticationRequired(AuthenticationRequiredType.DisabledForLocalhost);

            Subject.Check().ShouldBeOk();
        }

        [Test]
        public void should_return_warning_when_disabled()
        {
            GivenAuthenticationRequired(AuthenticationRequiredType.Disabled);

            Subject.Check().ShouldBeWarning();
        }

        [Test]
        public void should_return_warning_when_disabled_for_local_addresses()
        {
            GivenAuthenticationRequired(AuthenticationRequiredType.DisabledForLocalAddresses);

            Subject.Check().ShouldBeWarning();
        }

        [Test]
        public void should_return_warning_when_disabled_for_custom_addresses()
        {
            GivenAuthenticationRequired(AuthenticationRequiredType.DisabledForCustomAddresses);

            Subject.Check().ShouldBeWarning();
        }
    }
}
