using NUnit.Framework;
using NzbDrone.Core.Authentication;

namespace NzbDrone.Core.Test.Authentication
{
    [TestFixture]
    public class AuthenticationRequiredTypeFixture
    {
        // These ordinals are persisted in config.xml. Enabled=0,
        // DisabledForLocalAddresses=1, and DisabledForLocalhost=2 predate
        // this enum's expansion and must never be renumbered, or every
        // existing user's saved configuration would silently mean something
        // different after an upgrade. New values are appended with the next
        // unused ordinal instead of being inserted.
        [TestCase(AuthenticationRequiredType.Enabled, 0)]
        [TestCase(AuthenticationRequiredType.DisabledForLocalAddresses, 1)]
        [TestCase(AuthenticationRequiredType.DisabledForLocalhost, 2)]
        [TestCase(AuthenticationRequiredType.Disabled, 3)]
        [TestCase(AuthenticationRequiredType.DisabledForCustomAddresses, 4)]
        public void ordinal_values_must_remain_stable_for_upgrade_path(AuthenticationRequiredType value, int expectedOrdinal)
        {
            Assert.AreEqual(expectedOrdinal, (int)value);
        }
    }
}
