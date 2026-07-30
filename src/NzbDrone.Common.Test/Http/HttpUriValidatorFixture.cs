using System.Net;
using FluentAssertions;
using NUnit.Framework;
using NzbDrone.Common.Http;
using NzbDrone.Test.Common;

namespace NzbDrone.Common.Test.Http
{
    [TestFixture]
    public class HttpUriValidatorFixture : TestBase
    {
        [TestCase("http://8.8.8.8/cover.jpg")]
        [TestCase("https://1.1.1.1/cover.jpg")]
        [TestCase("http://93.184.216.34/cover.jpg")]
        public void should_allow_public_ipv4_literal_address(string url)
        {
            HttpUriValidator.IsSafeExternalUrl(url, out var reason).Should().BeTrue();
            reason.Should().BeNull();
        }

        [TestCase("http://[2606:4700:4700::1111]/cover.jpg")]
        public void should_allow_public_ipv6_literal_address(string url)
        {
            HttpUriValidator.IsSafeExternalUrl(url, out var reason).Should().BeTrue();
            reason.Should().BeNull();
        }

        [TestCase("")]
        [TestCase(" ")]
        [TestCase(null)]
        public void should_reject_empty_url(string url)
        {
            HttpUriValidator.IsSafeExternalUrl(url, out var reason).Should().BeFalse();
            reason.Should().NotBeNullOrEmpty();
        }

        [TestCase("not-a-url")]
        [TestCase("/relative/path.jpg")]
        public void should_reject_non_absolute_url(string url)
        {
            HttpUriValidator.IsSafeExternalUrl(url, out var reason).Should().BeFalse();
        }

        [TestCase("ftp://8.8.8.8/cover.jpg")]
        [TestCase("file:///etc/passwd")]
        public void should_reject_unsupported_scheme(string url)
        {
            HttpUriValidator.IsSafeExternalUrl(url, out var reason).Should().BeFalse();
            reason.Should().NotBeNullOrEmpty();

            ExceptionVerification.ExpectedWarns(1);
        }

        [TestCase("ftp://8.8.8.8/cover.jpg")]
        [TestCase("file:///etc/passwd")]
        public void should_allow_unsupported_scheme_when_optout_enabled(string url)
        {
            HttpUriValidator.IsSafeExternalUrl(url, out var reason, allowNonHttpSchemes: true).Should().BeTrue();
            reason.Should().BeNull();

            // Even though the request is allowed through, it must still be
            // reported: the opt-out only controls whether the request is
            // followed, never whether it is logged.
            ExceptionVerification.ExpectedWarns(1);
        }

        [TestCase("http://127.0.0.1/cover.jpg")]
        [TestCase("http://127.0.0.1:8080/admin")]
        [TestCase("http://[::1]/cover.jpg")]
        public void should_always_block_loopback_regardless_of_rfc1918_optout(string url)
        {
            HttpUriValidator.IsSafeExternalUrl(url, out var reason, allowRfc1918Addresses: true).Should().BeFalse();
            reason.Should().NotBeNullOrEmpty();

            ExceptionVerification.ExpectedErrors(1);
        }

        [TestCase("http://169.254.169.254/latest/meta-data/")]
        [TestCase("http://[fe80::1]/cover.jpg")]
        public void should_always_block_link_local_regardless_of_rfc1918_optout(string url)
        {
            HttpUriValidator.IsSafeExternalUrl(url, out var reason, allowRfc1918Addresses: true).Should().BeFalse();
            reason.Should().NotBeNullOrEmpty();

            ExceptionVerification.ExpectedErrors(1);
        }

        [TestCase("http://0.0.0.0/cover.jpg")]
        [TestCase("http://[::]/cover.jpg")]
        [TestCase("http://0.1.2.3/cover.jpg")]
        public void should_always_block_unspecified_and_this_network_addresses(string url)
        {
            HttpUriValidator.IsSafeExternalUrl(url, out var reason, allowRfc1918Addresses: true).Should().BeFalse();
            reason.Should().NotBeNullOrEmpty();

            ExceptionVerification.ExpectedErrors(1);
        }

        [TestCase("http://10.0.0.5/cover.jpg")]
        [TestCase("http://172.16.0.5/cover.jpg")]
        [TestCase("http://192.168.1.5/cover.jpg")]
        [TestCase("http://[fc00::1]/cover.jpg")]
        public void should_block_rfc1918_addresses_by_default(string url)
        {
            HttpUriValidator.IsSafeExternalUrl(url, out var reason).Should().BeFalse();
            reason.Should().NotBeNullOrEmpty();

            ExceptionVerification.ExpectedErrors(1);
        }

        [TestCase("http://10.0.0.5/cover.jpg")]
        [TestCase("http://172.16.0.5/cover.jpg")]
        [TestCase("http://192.168.1.5/cover.jpg")]
        [TestCase("http://[fc00::1]/cover.jpg")]
        public void should_allow_rfc1918_addresses_when_optout_enabled(string url)
        {
            HttpUriValidator.IsSafeExternalUrl(url, out var reason, allowRfc1918Addresses: true).Should().BeTrue();
            reason.Should().BeNull();

            // Even though the request is allowed through, it must still be
            // reported: the opt-out only controls whether the request is
            // followed, never whether it is logged.
            ExceptionVerification.ExpectedErrors(1);
        }

        [TestCase("http://100.64.0.5/cover.jpg")]
        [TestCase("http://100.100.100.100/cover.jpg")]
        public void should_block_cgnat_addresses_regardless_of_rfc1918_optout(string url)
        {
            // CGNAT (100.64.0.0/10) is not RFC1918, so the opt-out must not
            // affect it -- it remains blocked either way.
            HttpUriValidator.IsSafeExternalUrl(url, out var reason, allowRfc1918Addresses: true).Should().BeFalse();
            reason.Should().NotBeNullOrEmpty();

            ExceptionVerification.ExpectedErrors(1);
        }

        [Test]
        public void should_report_full_url_source_url_and_resolved_address_when_blocked()
        {
            const string maliciousUrl = "http://192.168.1.50/cover.jpg";
            const string providerUrl = "https://metadata-provider.example.com/api/movie/123";

            HttpUriValidator.IsSafeExternalUrl(maliciousUrl, out _, allowRfc1918Addresses: false, sourceUrl: providerUrl).Should().BeFalse();

            ExceptionVerification.ExpectedErrors(1);
        }
    }
}
