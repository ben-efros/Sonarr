using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using NLog;
using NzbDrone.Common.Cache;
using NzbDrone.Common.Extensions;
using NzbDrone.Common.Http;
using NzbDrone.Common.Instrumentation;
using NzbDrone.Core.Configuration;

namespace NzbDrone.Core.MediaCover
{
    public interface IMediaCoverProxy
    {
        string RegisterUrl(string url, string sourceUrl = null);

        string GetUrl(string hash);
        Task<byte[]> GetImage(string hash);
    }

    public class MediaCoverProxy : IMediaCoverProxy
    {
        private static readonly Logger Logger = NzbDroneLogger.GetLogger(typeof(MediaCoverProxy));

        private readonly IHttpClient _httpClient;
        private readonly IConfigFileProvider _configFileProvider;
        private readonly ICached<string> _cache;
        private readonly ICached<string> _sourceUrlCache;

        public MediaCoverProxy(IHttpClient httpClient, IConfigFileProvider configFileProvider, ICacheManager cacheManager)
        {
            _httpClient = httpClient;
            _configFileProvider = configFileProvider;
            _cache = cacheManager.GetCache<string>(GetType());
            _sourceUrlCache = cacheManager.GetCache<string>(GetType(), "sourceUrls");
        }

        public string RegisterUrl(string url, string sourceUrl = null)
        {
            if (url.IsNullOrWhiteSpace())
            {
                return null;
            }

            if (!HttpUriValidator.IsSafeExternalUrl(url, out _, _configFileProvider.AllowRfc1918UrlsFromExternalSources, sourceUrl, _configFileProvider.AllowNonHttpSchemesFromExternalSources))
            {
                return null;
            }

            var hash = url.SHA256Hash();

            _cache.Set(hash, url, TimeSpan.FromHours(24));
            _sourceUrlCache.Set(hash, sourceUrl ?? "unknown", TimeSpan.FromHours(24));

            _cache.ClearExpired();
            _sourceUrlCache.ClearExpired();

            var fileName = Path.GetFileName(url);
            return _configFileProvider.UrlBase + @"/MediaCoverProxy/" + hash + "/" + fileName;
        }

        public string GetUrl(string hash)
        {
            var result = _cache.Find(hash);

            if (result == null)
            {
                throw new KeyNotFoundException("Url no longer in cache");
            }

            return result;
        }

        public async Task<byte[]> GetImage(string hash)
        {
            var url = GetUrl(hash);
            var sourceUrl = _sourceUrlCache.Find(hash);
            var allowRfc1918 = _configFileProvider.AllowRfc1918UrlsFromExternalSources;
            var allowNonHttpSchemes = _configFileProvider.AllowNonHttpSchemesFromExternalSources;

            if (!HttpUriValidator.IsSafeExternalUrl(url, out var reason, allowRfc1918, sourceUrl, allowNonHttpSchemes))
            {
                throw new UnauthorizedAccessException($"Refusing to fetch cover image: {reason} ({url})");
            }

            var request = new HttpRequest(url)
            {
                UrlValidator = u => HttpUriValidator.IsSafeExternalUrl(u, out _, allowRfc1918, sourceUrl, allowNonHttpSchemes)
            };
            var response = await _httpClient.GetAsync(request);

            return response.ResponseData;
        }
    }
}
