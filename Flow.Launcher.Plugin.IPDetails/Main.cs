using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using Flow.Launcher.Plugin.IPDetails.Settings;
using Flow.Launcher.Plugin.SharedCommands;

namespace Flow.Launcher.Plugin.IPDetails
{
    /// <inheritdoc cref="Flow.Launcher.Plugin.IAsyncPlugin" />
    /// <inheritdoc cref="Flow.Launcher.Plugin.ISettingProvider" />
    public class Main : IAsyncPlugin, ISettingProvider
    {
        private PluginInitContext Context { get; set; }
        private static readonly HttpClient HttpClient = new();

        // List of service URLs to try, in order of preference.
        // Using HTTPS where available. All these return plain text IP.
        private static readonly List<string> IpServiceUrls = new List<string>
        {
            "https://api.ipify.org",    // Primary choice: Simple, fast, reliable
            "https://ipinfo.io/ip",    // Good fallback
            "https://ipv4.icanhazip.com"   // Another solid option
            // Add more plain-text IP services here if needed
        };

        /// <summary>
        /// <a href="https://www.flaticon.com/free-icons/ip" title="IP icons">IP icons created by Design Circle - Flaticon</a>
        /// </summary>
        private const string Icon = "images/icon.png";

        private static string _cacheFilePath;
        private static Settings.Settings _settings;

        private static readonly TimeSpan CacheExpiration = TimeSpan.FromDays(1);

        private static readonly JsonSerializerOptions JsonSerializerOptions = new()
        {
            Converters = { new IsVpnConverter() }
        };

        /// <inheritdoc />
        public Task InitAsync(PluginInitContext context)
        {
            Context = context;

            _settings = context.API.LoadSettingJsonStorage<Settings.Settings>();

            _cacheFilePath =
                Path.Combine(Context.CurrentPluginMetadata.PluginDirectory, "cache/ipapi_cache.json");

            Directory.CreateDirectory(Path.GetDirectoryName(_cacheFilePath)!);

            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public async Task<List<Result>> QueryAsync(Query query, CancellationToken cancellationToken)
        {
            var results = new List<Result>
            {
                new()
                {
                    Title = "Fetching IP details...",
                    SubTitle = "Please wait",
                    IcoPath = Icon
                }
            };

            try
            {
                var response = await FetchIpApiResponse(await GenerateUrl(query.Search));

                // Remove the initial placeholder result
                results.RemoveAt(0);

                results.Add(new Result
                {
                    Title = response.Ip,
                    SubTitle = "Public IP",
                    IcoPath = Icon,
                    Action = CreateCopyAction(response.Ip),
                    Score = 99
                });

                var location = string.Join(", ",
                    new[] { response.Location.City, response.Location.State, response.Location.Country }
                        .Where(l => !string.IsNullOrEmpty(l)));

                results.Add(new Result
                {
                    Title = location,
                    SubTitle = "Location",
                    IcoPath = Icon,
                    Action = CreateCopyAction(location),
                    Score = 98
                });

                results.Add(new Result
                {
                    Title = response.Asn.Org,
                    SubTitle = "ISP",
                    IcoPath = Icon,
                    Action = CreateCopyAction(response.Asn.Org),
                    Score = 97
                });

                results.Add(new Result
                {
                    Title = response.Location.Timezone,
                    SubTitle = "Timezone / " + response.Location.LocalTime,
                    IcoPath = Icon,
                    Action = CreateCopyAction(response.Location.Timezone),
                    Score = 96
                });

                var isVpnFromBoolean = response.IsVpn is true;
                var isVpnProviderAvailable = response.IsVpn is string;

                var isVpnString = isVpnFromBoolean
                    ? "VPN"
                    : isVpnProviderAvailable
                        ? response.IsVpn.ToString()
                        : string.Empty;

                var flags = new (string Title, bool IsValid, string Subtitle)[]
                {
                    ("Bogon", response.IsBogon, "IP is bogon (non-routable)"),
                    ("Mobile", response.IsMobile, "IP is mobile (belongs to a mobile ISP)"),
                    ("Crawler", response.IsCrawler, "IP belongs to a crawler / spider / good bot"),
                    ("Datacenter", response.IsDatacenter, "IP belongs to a Hosting Provider / Datacenter"),
                    ("Tor", response.IsTor, "IP is a TOR exit node"),
                    ("Proxy", response.IsProxy, "IP is a proxy"),
                    (isVpnString, isVpnFromBoolean || isVpnProviderAvailable, "IP is a VPN"),
                    ("Abuser", response.IsAbuser, "IP detected as an abuser / attacker")
                };

                results.AddRange(flags.Where(flag => flag.IsValid)
                    .Select(flag => new Result
                    {
                        Title = flag.Title,
                        SubTitle = flag.Subtitle,
                        IcoPath = Icon,
                        Action = CreateCopyAction(flag.Subtitle),
                        Score = 95
                    }));

                var googleMapsLink = GenerateGoogleMapsLink(response.Location.LatitudeFormatted,
                    response.Location.LongitudeFormatted);

                results.Add(new Result
                {
                    Title =
                        $"Latitude: {response.Location.LatitudeFormatted}, Longitude: {response.Location.LongitudeFormatted}",
                    SubTitle = "Click to view coordinate on Google Maps",
                    IcoPath = Icon,
                    Action = CreateOpenBrowserAction(googleMapsLink),
                });
            }
            catch (Exception ex)
            {
                results.Add(new Result
                {
                    Title = "An error occurred while fetching IP details",
                    SubTitle = ex.Message,
                    IcoPath = Icon,
                    Action = CreateCopyAction(ex.Message)
                });
            }

            return results;
        }

        private static Func<ActionContext, bool> CreateCopyAction(string text)
        {
            return _ =>
            {
                Clipboard.SetDataObject(text);
                return false;
            };
        }

        private static Func<ActionContext, bool> CreateOpenBrowserAction(string link)
        {
            return _ =>
            {
                link.OpenInBrowserTab();
                return true;
            };
        }

        private static string GenerateGoogleMapsLink(string latitude, string longitude)
        {
            return $"https://www.google.com/maps?q={latitude},{longitude}";
        }

        /// <summary>
        /// Attempts to get the public IP address by trying multiple free services sequentially.
        /// </summary>
        /// <param name="timeoutSeconds">Optional timeout per service request.</param>
        /// <returns>The public IP address as a string, or null if all services failed or timed out.</returns>
        public static async Task<string?> GetPublicIpAddressAsync(int timeoutSeconds = 5)
        {
            var errors = new List<string>();
            // Use a CancellationTokenSource for timeout per request
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds)))
            {
                foreach (var url in IpServiceUrls)
                {
                    try
                    {
                        // Make the request with the cancellation token
                        string potentialIp = (await HttpClient.GetStringAsync(url, cts.Token)).Trim();
    
                        // Basic validation: Check if the response looks like a valid IP address
                        if (!string.IsNullOrEmpty(potentialIp) && IPAddress.TryParse(potentialIp, out _))
                        {
                            return potentialIp; // Success! Return the first valid IP found.
                        }
                        else 
                        {
                            errors.Add($"Service {url} returned invalid data: '{potentialIp}'");
                        }
                    }
                    catch (OperationCanceledException ex) when (cts.IsCancellationRequested)
                    {
                        // This specifically catches the timeout we set
                        errors.Add($"Request to {url} timed out after {timeoutSeconds} seconds.");
                    }
                    catch (HttpRequestException ex)
                    {
                        // Network error, DNS error, service unavailable, etc.
                        errors.Add($"Failed to get IP from {url}. Error: {ex.Message}");
                    }
                    catch (Exception ex) // Catch any other unexpected errors
                    {
                        errors.Add($"An unexpected error occurred trying {url}. Error: {ex.Message}");
                    }
                    // If we reach here, the current service failed or timed out,
                    // loop will continue to the next service.
                }
            } // CancellationTokenSource is disposed here
    
            // If the loop completes without returning, all services failed.
            // Throw an exception containing the *last* error encountered.
            if (errors.Any()) // Check if there are any errors before accessing Last()
            {
                 // Consider joining all errors for more context:
                 // string allErrors = string.Join("; ", errors);
                 // throw new Exception($"Failed to retrieve public IP from all services. Errors: {allErrors}");
    
                 // Throwing only the last error as per your code:
                 throw new Exception($"Failed to retrieve public IP. Last error: {errors.Last()}");
            }
            else
            {
                // This case is unlikely with the current logic but handles completeness
                throw new Exception("Failed to retrieve public IP from all services for an unknown reason (no specific errors recorded).");
            }
        }

        private static async Task<string> GenerateUrl(string ip)
        {
            var (isValid, ipFormatted) = IsValidIPv4(ip);

            if (string.IsNullOrEmpty(ip) || !isValid)
            {
                ipFormatted = await GetPublicIpAddressAsync(); // Call the robust fetcher
            }

            var apiKeyQueryString = string.IsNullOrEmpty(_settings.ApiKey)
                ? string.Empty
                : $"&key={_settings.ApiKey}";

            return $"https://api.ipapi.is/?q={ipFormatted}{apiKeyQueryString}";
        }

        private static (bool, string) IsValidIPv4(string ipString)
        {
            var splitValues = ipString.Split('.');

            if (splitValues.Length != 4)
            {
                return (false, string.Empty);
            }

            if (!IPAddress.TryParse(ipString, out var ipAddress))
            {
                return (false, string.Empty);
            }

            if (ipAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return (false, string.Empty);
            }

            if (IsPrivateOrBogonIp(ipAddress))
            {
                return (false, string.Empty);
            }

            return (true, ipAddress.ToString());
        }

        private static async Task<IpApiResponse> FetchIpApiResponse(string url)
        {
            if (TryGetCachedResponse(url, out IpApiResponse cachedResponse))
            {
                return cachedResponse;
            }

            var responseString = await HttpClient.GetStringAsync(url);

            var apiResponse = JsonSerializer.Deserialize<IpApiResponse>(responseString, JsonSerializerOptions);

            CacheResponse(url, apiResponse);

            return apiResponse;
        }

        private static bool TryGetCachedResponse(string url, out IpApiResponse cachedResponse)
        {
            cachedResponse = null;

            if (!File.Exists(_cacheFilePath))
            {
                // Create an empty cache file
                File.WriteAllText(_cacheFilePath, "{}");

                return false;
            }

            var cacheData =
                JsonSerializer.Deserialize<Dictionary<string, CachedIpApiResponse>>(File.ReadAllText(_cacheFilePath));

            if (cacheData == null || !cacheData.TryGetValue(url, out var cachedEntry))
            {
                return false;
            }

            // Remove all expired cache entries
            foreach (var (key, value) in cacheData)
            {
                if (DateTime.UtcNow - value.Timestamp >= CacheExpiration)
                {
                    cacheData.Remove(key);
                }
            }

            if (DateTime.UtcNow - cachedEntry.Timestamp < CacheExpiration)
            {
                cachedResponse = cachedEntry.Response;

                return true;
            }

            File.WriteAllText(_cacheFilePath, JsonSerializer.Serialize(cacheData));

            return false;
        }

        private static void CacheResponse(string url, IpApiResponse response)
        {
            Dictionary<string, CachedIpApiResponse> cacheData;

            if (File.Exists(_cacheFilePath))
            {
                cacheData =
                    JsonSerializer
                        .Deserialize<Dictionary<string, CachedIpApiResponse>>(File.ReadAllText(_cacheFilePath)) ??
                    new Dictionary<string, CachedIpApiResponse>();
            }
            else
            {
                cacheData = new Dictionary<string, CachedIpApiResponse>();
            }

            cacheData[url] = new CachedIpApiResponse
            {
                Timestamp = DateTime.UtcNow,
                Response = response
            };

            File.WriteAllText(_cacheFilePath, JsonSerializer.Serialize(cacheData));
        }

        private static bool IsPrivateOrBogonIp(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            switch (bytes[0])
            {
                case 10 or 127:
                case 172 when bytes[1] >= 16 && bytes[1] <= 31:
                case 192 when bytes[1] == 168:
                case 169 when bytes[1] == 254:
                case 100 when bytes[1] >= 64 && bytes[1] <= 127:
                case 198 when bytes[1] == 18 || bytes[1] == 19 || bytes[1] == 51 || bytes[1] == 52:
                case 203 when bytes[1] == 0 && bytes[2] == 113:
                case 240 or 255:
                    return true;
                default:
                    return false;
            }
        }

        /// <inheritdoc />
        public Control CreateSettingPanel()
        {
            return new SettingsControl(_settings);
        }
    }
}
