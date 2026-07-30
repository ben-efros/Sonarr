using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace NzbDrone.Common.Extensions
{
    // A minimal, framework-independent representation of a CIDR range
    // (e.g. "10.0.0.0/8" or "fc00::/7"), with membership testing done via
    // simple bitwise comparison rather than relying on
    // Microsoft.AspNetCore.HttpOverrides.IPNetwork or System.Net.IPNetwork,
    // whose availability/shape differs between the older and newer .NET
    // targets used by Radarr and Sonarr respectively.
    public readonly struct CidrRange
    {
        public IPAddress Address { get; }
        public int PrefixLength { get; }

        public CidrRange(IPAddress address, int prefixLength)
        {
            Address = address;
            PrefixLength = prefixLength;
        }

        public bool Contains(IPAddress address)
        {
            if (address == null)
            {
                return false;
            }

            var candidate = Normalize(address);
            var network = Normalize(Address);

            if (candidate.AddressFamily != network.AddressFamily)
            {
                return false;
            }

            var candidateBytes = candidate.GetAddressBytes();
            var networkBytes = network.GetAddressBytes();

            var fullBytes = PrefixLength / 8;
            var remainingBits = PrefixLength % 8;

            for (var i = 0; i < fullBytes; i++)
            {
                if (candidateBytes[i] != networkBytes[i])
                {
                    return false;
                }
            }

            if (remainingBits > 0 && fullBytes < candidateBytes.Length)
            {
                var mask = (byte)(0xFF << (8 - remainingBits));

                if ((candidateBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask))
                {
                    return false;
                }
            }

            return true;
        }

        private static IPAddress Normalize(IPAddress address)
        {
            return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        }
    }

    public static class CidrUtils
    {
        public static bool TryParseCidr(string cidr, out CidrRange range)
        {
            range = default;

            if (cidr.IsNullOrWhiteSpace())
            {
                return false;
            }

            var parts = cidr.Trim().Split('/');

            if (parts.Length != 2 ||
                !IPAddress.TryParse(parts[0], out var address) ||
                !int.TryParse(parts[1], out var prefixLength))
            {
                return false;
            }

            // IPv4 addresses allow a prefix length of at most 32; IPv6 allows up to 128.
            var maxPrefixLength = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;

            if (prefixLength < 0 || prefixLength > maxPrefixLength)
            {
                return false;
            }

            range = new CidrRange(address, prefixLength);
            return true;
        }

        public static IEnumerable<string> SplitCidrList(string cidrList)
        {
            if (cidrList.IsNullOrWhiteSpace())
            {
                yield break;
            }

            foreach (var entry in cidrList.Split(new[] { ',', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = entry.Trim();

                if (trimmed.Length > 0)
                {
                    yield return trimmed;
                }
            }
        }

        // A list is valid only if it contains at least one entry and every
        // entry parses as a valid, address-family-appropriate CIDR.
        public static bool IsValidCidrList(string cidrList)
        {
            var entries = SplitCidrList(cidrList).ToList();

            return entries.Count > 0 && entries.All(entry => TryParseCidr(entry, out _));
        }

        public static bool IsAddressInAnyCidr(IPAddress address, string cidrList)
        {
            if (address == null)
            {
                return false;
            }

            foreach (var entry in SplitCidrList(cidrList))
            {
                if (TryParseCidr(entry, out var range) && range.Contains(address))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
