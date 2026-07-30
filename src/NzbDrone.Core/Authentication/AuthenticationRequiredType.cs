namespace NzbDrone.Core.Authentication
{
    public enum AuthenticationRequiredType
    {
        Enabled = 0,
        DisabledForLocalAddresses = 1,
        DisabledForLocalhost = 2,
        Disabled = 3,
        DisabledForCustomAddresses = 4,
    }
}
