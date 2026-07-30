using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using NLog;
using NzbDrone.Common.Extensions;
using NzbDrone.Common.Instrumentation;

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
    //
    // NOTE: this check only applies to URLs sourced from external/untrusted
    // data (metadata provider responses, indexer responses, etc). URLs
    // explicitly entered by the user (e.g. in settings) are trusted and must
    // not be routed through this validator.
    public static class HttpUriValidator
    {
        private static readonly Logger Logger = NzbDroneLogger.GetLogger(typeof(HttpUriValidator));

        // allowRfc1918Addresses is an explicit, narrowly-scoped opt-out (an
        // "advanced" user setting, off/secure by default) for locally-hosted
        // metadata/image servers living on the user's own private network. It
        // never widens the check to loopback, link-local, CGNAT or IPv6
        // ULA-equivalent exclusions -- those remain blocked unconditionally,
        // regardless of this flag.
        //
        // sourceUrl is purely informational: the URL/description of the
        // external request (e.g. a metadata provider API call) whose
        // response contained the possibly-malicious url being validated
        // here. It is only used for logging so operators can trace which
        // provider/source produced the flagged url.
        //
        // Regardless of whether the address ends up allowed (via
        // allowRfc1918Addresses) or blocked, every detected
        // loopback/private/link-local/unspecified address is always logged
        // at Error level -- this setting only controls whether the request
        // is *followed*, never whether it is *reported*.
        public static bool IsSafeExternalUrl(string url, out string reason, bool allowRfc1918Addresses = false, string sourceUrl = null, bool allowNonHttpSchemes = false)
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
                if (allowNonHttpSchemes)
                {
                    LogUnsupportedScheme(url, sourceUrl, uri.Scheme, "Allowed via AllowNonHttpSchemesFromExternalSources");
                    return true;
                }

                reason = $"Unsupported scheme '{uri.Scheme}'. Only http/https URLs are allowed by default as a defense against SSRF. " +
                    "To allow this scheme, enable 'Allow Non-HTTP(S) URLs From External Sources' under Settings > General > Security (or set AllowNonHttpSchemesFromExternalSources in config.xml).";
                LogUnsupportedScheme(url, sourceUrl, uri.Scheme, "Blocked");
                return false;
            }

            IPAddress[] addresses;

            if (IPAddress.TryParse(uri.Host, out var literalAddress))
            {
                addresses = new[] { literalAddress };
            }
            else
            {
                try
                {
                    addresses = Dns.GetHostAddresses(uri.Host);
                }
                catch (Exception)
                {
                    reason = $"Unable to resolve host '{uri.Host}'";
                    return false;
                }

                if (addresses.Length == 0)
                {
                    reason = $"Host '{uri.Host}' did not resolve to any address";
                    return false;
                }
            }

            var blockedAddresses = new List<IPAddress>();
            var allowedPrivateAddresses = new List<IPAddress>();

            foreach (var address in addresses)
            {
                if (!IsUnsafeAddress(address, out var isRfc1918Only))
                {
                    continue;
                }

                if (allowRfc1918Addresses && isRfc1918Only)
                {
                    allowedPrivateAddresses.Add(address);
                }
                else
                {
                    blockedAddresses.Add(address);
                }
            }

            if (allowedPrivateAddresses.Count > 0)
            {
                LogUnsafeUrl(url, sourceUrl, "Allowed via AllowRfc1918UrlsFromExternalSources", allowedPrivateAddresses);
            }

            if (blockedAddresses.Count > 0)
            {
                reason = $"Host '{uri.Host}' resolves to a loopback/private/link-local/unspecified address";
                LogUnsafeUrl(url, sourceUrl, "Blocked", blockedAddresses);
                return false;
            }

            return true;
        }

        private static void LogUnsupportedScheme(string url, string sourceUrl, string scheme, string outcome)
        {
            // Always logged, regardless of the allowNonHttpSchemes setting:
            // an externally-sourced URL using a scheme other than http/https
            // is unusual enough to warrant visibility whether or not the
            // request was ultimately permitted through the advanced opt-out.
            Logger.Warn(
                "Detected externally-sourced URL with unsupported scheme '{0}'. Outcome: {1} Url: {2} SourceUrl: {3}",
                scheme,
                outcome,
                url,
                sourceUrl.IsNullOrWhiteSpace() ? "unknown" : sourceUrl);
        }

        private static void LogUnsafeUrl(string url, string sourceUrl, string outcome, List<IPAddress> resolvedAddresses)
        {
            var addressList = string.Join(", ", resolvedAddresses.Select(a => a.ToString()));

            // Always logged at Error, regardless of the allowRfc1918Addresses
            // setting: this indicates either a misconfigured/compromised
            // external source or an attempted SSRF probe, and operators must
            // be able to see it happened even if the request was ultimately
            // permitted through the advanced opt-out.
            Logger.Error(
                "Detected unsafe outbound request to a loopback/private/link-local/unspecified address. Outcome: {0} Url: {1} ResolvedAddresses: [{2}] SourceUrl: {3}",
                outcome,
                url,
                addressList,
                sourceUrl.IsNullOrWhiteSpace() ? "unknown" : sourceUrl);
        }

        // True if the address is one that must never be reachable via an
        // externally-sourced URL by default (loopback, link-local, RFC1918
        // private-use, IPv6 ULA, CGNAT, and the unspecified/"any" addresses).
        // isRfc1918Only is true only when the sole reason the address is
        // considered unsafe is that it's RFC1918/ULA private-use space --
        // i.e. the narrow case the AllowRfc1918UrlsFromExternalSources opt-out
        // is allowed to override. Loopback and link-local addresses are never
        // eligible for the opt-out, even if they also happen to overlap with
        // a private range.
        private static bool IsUnsafeAddress(IPAddress address, out bool isRfc1918Only)
        {
            isRfc1918Only = false;

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

            // CGNAT (100.64.0.0/10) is carrier-grade NAT space, not RFC1918
            // private-use space -- it's routed by ISPs between customers and
            // their NAT gateway, so it must never be eligible for the
            // RFC1918-only opt-out.
            if (address.IsCgnatIpAddress())
            {
                return true;
            }

            if (!address.IsLocalAddress())
            {
                return false;
            }

            isRfc1918Only = address.IsRfc1918Address() && !IPAddress.IsLoopback(address);

            return true;
        }
    }
}
