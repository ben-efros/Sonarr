namespace NzbDrone.Core.Security
{
    public enum XForwardedForTrustLevel
    {
        // Trust X-Forwarded-For/-Proto/-Host headers from any peer whose direct
        // connection originates from an RFC1918 private address range. This was
        // the historical, hardcoded behavior and remains the default for
        // backwards compatibility, but is overly broad for hosts that aren't
        // sitting behind a dedicated reverse proxy (e.g. plain LAN deployments).
        Rfc1918 = 0,

        // Trust only the CIDR ranges explicitly listed in TrustedProxyCidrs.
        Custom = 1,

        // Don't trust forwarded headers from any non-loopback peer.
        Disabled = 2
    }
}
