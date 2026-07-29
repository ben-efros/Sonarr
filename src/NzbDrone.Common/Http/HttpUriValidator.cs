using System;
using System.Linq;
using System.Net;
using NzbDrone.Common.Extensions;

namespace NzbDrone.Common.Http
{
    // Guards against Server-Side Request Forgery (SSRF): validates that a URL
    // pulled from an external, untrusted source (e.g. a metadata provider's
    // JSON response) is safe for this application to fetch server-side before
    // handing it to HttpClient. Without this check, a malicious/compromised
    // metadata source could return an "image" URL pointing at an internal-only
    // service (e.g. http://169.254.169.254/, http://localhost:<port>/) and have
    // the server fetch it -- and, via MediaCoverProxy, even proxy the response
    // bytes back to any client that requests the proxy URL.
    public static class HttpUriValidator
    {
        public static bool IsSafeExternalUrl(string url, out string reason)
        {
            reason = null;

            if (url.IsNullOrWhiteSpace())
            {
                reason = "URL is empty";
                return false;
            }

            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                reason = "Not a valid absolute URL";
                return false;
            }

            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
            {
                reason = $"Unsupported scheme '{uri.Scheme}'";
                return false;
            }

            if (IPAddress.TryParse(uri.Host, out var literalAddress))
            {
                if (IsBlockedAddress(literalAddress))
                {
                    reason = $"Host '{uri.Host}' is a loopback/private/link-local/unspecified address";
                    return false;
                }

                return true;
            }

            IPAddress[] addresses;

            try
            {
                addresses = Dns.GetHostAddresses(uri.Host);
            }
            catch (Exception)
            {
                reason = $"Unable to resolve host '{uri.Host}'";
                return false;
            }

            if (addresses.Length == 0 || addresses.Any(IsBlockedAddress))
            {
                reason = $"Host '{uri.Host}' resolves to a loopback/private/link-local/unspecified address";
                return false;
            }

            return true;
        }

        private static bool IsBlockedAddress(IPAddress address)
        {
            // IPAddress.Any (0.0.0.0) / IPv6Any (::) and the 0.0.0.0/8 "this
            // network" range are not covered by IsLocalAddress() but are
            // treated as loopback/unroutable by many HTTP stacks.
            if (IPAddress.Any.Equals(address) || IPAddress.IPv6Any.Equals(address))
            {
                return true;
            }

            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                address.GetAddressBytes()[0] == 0)
            {
                return true;
            }

            return address.IsLocalAddress();
        }
    }
}
