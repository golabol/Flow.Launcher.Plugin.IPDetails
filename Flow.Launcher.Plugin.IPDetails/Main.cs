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
            string apiTarget = query.Search ?? "your public IP"; // Default display target
            var fetchedResults = new List<Result>
            {
                new()
                {
                    Title = "Fetching IP details...",
                    SubTitle = $"Looking up: {apiTarget}", // Use display target
                    IcoPath = Icon
                }
            };

            try
            {
                // Determine the target (IP or domain) for the API call
                apiTarget = await GetApiTargetAsync(query.Search);

                // Build the URL using the determined target
                string apiUrl = BuildApiUrl(apiTarget);

                // Fetch data using the constructed URL
                var response = await FetchIpApiResponse(apiUrl, cancellationToken);

                // Remove the initial placeholder result
                fetchedResults.RemoveAt(0);

                if (response == null || string.IsNullOrEmpty(response.Ip))
                {
                    // Handle cases where the API call succeeded but returned minimal/no useful data
                     fetchedResults.Add(new Result
                     {
                         Title = $"No details found for: {apiTarget}",
                         SubTitle = "The API might not have information for this IP/domain, or the response was empty.",
                         IcoPath = Icon,
                         Score = 99
                     });
                     return fetchedResults; // Return early if no core IP info
                }
                
                fetchedResults.Add(new Result
                {
                    Title = response.Ip, // API response should have the resolved IP
                    SubTitle = $"Details for: {apiTarget}", // Show what was originally looked up
                    IcoPath = Icon,
                    Action = CreateCopyAction(response.Ip),
                    Score = 99
                });

                // Check if Location is null before accessing its properties
                if (response.Location != null)
                {
                    var locationParts = new[] { response.Location.City, response.Location.State, response.Location.Country };
                    var location = string.Join(", ", locationParts.Where(l => !string.IsNullOrEmpty(l)));

                    if (!string.IsNullOrWhiteSpace(location))
                    {
                        fetchedResults.Add(new Result
                        {
                            Title = location,
                            SubTitle = "Location",
                            IcoPath = Icon,
                            Action = CreateCopyAction(location),
                            Score = 98
                        });
                    }

                     if (!string.IsNullOrWhiteSpace(response.Location.Timezone))
                     {
                        fetchedResults.Add(new Result
                        {
                            Title = response.Location.Timezone,
                            SubTitle = "Timezone" + (!string.IsNullOrWhiteSpace(response.Location.LocalTime) ? $" / {response.Location.LocalTime}" : ""),
                            IcoPath = Icon,
                            Action = CreateCopyAction(response.Location.Timezone),
                            Score = 96
                        });
                     }

                     if (response.Location.Latitude != 0 || response.Location.Longitude != 0)
                     {
                         var googleMapsLink = GenerateGoogleMapsLink(response.Location.LatitudeFormatted,
                             response.Location.LongitudeFormatted);

                         fetchedResults.Add(new Result
                         {
                             Title =
                                 $"Lat: {response.Location.LatitudeFormatted}, Lon: {response.Location.LongitudeFormatted}",
                             SubTitle = "Click to view coordinate on Google Maps",
                             IcoPath = Icon,
                             Action = CreateOpenBrowserAction(googleMapsLink),
                             Score = 90
                         });
                    }
                }
                else {
                     Context.API.LogWarn(nameof(Main), $"Location info missing in API response for {apiTarget}.");
                }

                // Check if Asn is null before accessing its properties
                if (response.Asn != null && !string.IsNullOrWhiteSpace(response.Asn.Org))
                {
                    fetchedResults.Add(new Result
                    {
                        Title = response.Asn.Org,
                        SubTitle = "ISP / Organization",
                        IcoPath = Icon,
                        Action = CreateCopyAction(response.Asn.Org),
                        Score = 97
                    });
                } else {
                     Context.API.LogWarn(nameof(Main), $"ASN info missing in API response for {apiTarget}.");
                }

                 // --- Flags processing ---
                 var isVpnFromBoolean = response.IsVpn is bool vpnBool && vpnBool;
                 var isVpnProviderAvailable = response.IsVpn is string vpnString && !string.IsNullOrWhiteSpace(vpnString);
                 var isVpnString = isVpnFromBoolean ? "VPN Detected" : (isVpnProviderAvailable ? response.IsVpn.ToString() : string.Empty);

                 var flags = new (string Title, bool IsValid, string Subtitle)[]
                 {
                    ("Bogon", response.IsBogon, "IP is bogon (e.g., private, reserved)"),
                    ("Mobile", response.IsMobile, "IP is mobile (belongs to a mobile ISP)"),
                    ("Crawler", response.IsCrawler, "IP belongs to a crawler / spider / bot"),
                    ("Datacenter", response.IsDatacenter, "IP belongs to a Hosting Provider / Datacenter"),
                    ("Tor", response.IsTor, "IP is a TOR exit node"),
                    ("Proxy", response.IsProxy, "IP is a proxy"),
                    (isVpnString, !string.IsNullOrEmpty(isVpnString), isVpnProviderAvailable ? $"VPN Provider: {isVpnString}" : "IP is likely a VPN"),
                    ("Abuser", response.IsAbuser, "IP detected on abuse blacklists")
                 };

                 fetchedResults.AddRange(flags.Where(flag => flag.IsValid && !string.IsNullOrEmpty(flag.Title))
                     .Select(flag => new Result
                     {
                         Title = flag.Title,
                         SubTitle = flag.Subtitle,
                         IcoPath = Icon,
                         Action = CreateCopyAction(flag.Title + ": " + flag.Subtitle),
                         Score = 95 // Assign consistent score for flags
                     }));
            }
            catch (OperationCanceledException)
            {
                 // Query was cancelled (e.g., user typed something else)
                 Context.API.LogInfo(nameof(Main), "IP details query cancelled.");
                 // Return empty list or a specific cancellation message
                 fetchedResults.Add(new Result { Title = "IP details query cancelled", SubTitle = $"Query: {apiTarget}", IcoPath = Icon });
            }
            catch (Exception ex)
            {
                Context.API.LogWarn(nameof(Main), $"Error fetching IP details for '{apiTarget}': {ex.Message}", ex);
                // Ensure the placeholder is removed and error is shown
                fetchedResults.Clear(); // Clear any partial results
                fetchedResults.Add(new Result
                {
                    Title = $"Error fetching details for: {apiTarget}",
                    SubTitle = ex.Message, // Show the error message simply
                    IcoPath = Icon,
                    Action = CreateCopyAction($"Target: {apiTarget}\nError: {ex.Message}\n{ex.StackTrace}"), // Copy full error details
                    Score = 100 // Ensure error shows prominently
                });
            }

            // Return the final list of results (either details or an error message)
             if (!fetchedResults.Any())
             {
                // Should generally not happen due to error handling, but as a fallback
                 Context.API.LogWarn(nameof(Main), $"Query for '{apiTarget}' yielded no results or errors.");
                 fetchedResults.Add(new Result { Title = "No results found", SubTitle = $"Query: {apiTarget}", IcoPath = Icon });
             }

            return fetchedResults;
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

        // private static async Task<string> GenerateUrl(string ip)
        // {
        //     var (isValid, ipFormatted) = IsValidIPv4(ip);

        //     if (string.IsNullOrEmpty(ip) || !isValid)
        //     {
        //         ipFormatted = await GetPublicIpAddressAsync(); // Call the robust fetcher
        //     }

        //     var apiKeyQueryString = string.IsNullOrEmpty(_settings.ApiKey)
        //         ? string.Empty
        //         : $"&key={_settings.ApiKey}";

        //     return $"https://api.ipapi.is/?q={ipFormatted}{apiKeyQueryString}";
        // }

        private static async Task<string> GetApiTargetAsync(string userInput)
        {
            string target = userInput?.Trim() ?? string.Empty;

            // --- Input Cleaning ---
            if (Uri.TryCreate(target, UriKind.Absolute, out var uri) && (uri.Scheme == "http" || uri.Scheme == "https://"))
            {
                // If it's a valid URL, use the host part
                target = uri.DnsSafeHost;
            }
            else
            {
                // Remove potential schema manually if Uri.TryCreate failed but it looks like a URL start
                if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                    target = target.Substring(7);
                else if (target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    target = target.Substring(8);

                // Remove trailing slash if present
                target = target.TrimEnd('/');
                // Remove path part if contains slash after cleaning schema/trailing slash
                int pathSeparatorIndex = target.IndexOf('/');
                if (pathSeparatorIndex >= 0)
                {
                    target = target.Substring(0, pathSeparatorIndex);
                }
            }

            // Remove potential port number (ipapi.is doesn't use it)
            int portSeparatorIndex = target.LastIndexOf(':');
            // Avoid treating IPv6 colons as port separators
            if (portSeparatorIndex > 0 && target.IndexOf(']') < portSeparatorIndex)
            {
                 target = target.Substring(0, portSeparatorIndex);
            }


            // --- Target Determination ---
            if (string.IsNullOrEmpty(target))
            {
                // Case 1: Empty input -> Get own public IP
                return await GetPublicIpAddressAsync() ?? throw new Exception("Failed to determine own public IP and input was empty."); // Throw if own IP fails
            }

            if (IPAddress.TryParse(target, out var ipAddress))
            {
                // Case 2: Input is an IP address
                if (IsPublicIp(ipAddress))
                {
                    // It's a valid public IP (v4 or v6)
                    return ipAddress.ToString();
                }
                else
                {
                    // It's a private, loopback, or otherwise non-public IP.
                    // Let ipapi.is handle it, it might give some info or an error.
                    return ipAddress.ToString();
                     // ---- Alternative: Treat non-public IPs like empty input ----
                     // Console.WriteLine($"Input is a non-public IP ({ipAddress}), fetching own public IP instead.");
                     // return await GetPublicIpAddressAsync() ?? throw new Exception("Failed to determine own public IP and input was a non-public IP.");
                     // ---- Choose the alternative above if you PREFER to show your own IP details when a private IP is entered ----
                }
            }
            else
            {
                // Case 3: Input is not an IP address -> Assume domain/hostname
                return target; // Pass the domain/hostname directly to the API
            }
        }

        // ADD this new helper method to build the final URL
        private static string BuildApiUrl(string target)
        {
             var apiKeyQueryString = string.IsNullOrEmpty(_settings.ApiKey)
                ? string.Empty
                : $"&key={_settings.ApiKey}";

            // URL encode the target in case it's a domain with special characters (less common but safer)
            // However, ipapi.is seems fine without encoding simple domains/IPs. Let's skip encoding for now.
            // string encodedTarget = Uri.EscapeDataString(target);
            // return $"https://api.ipapi.is/?q={encodedTarget}{apiKeyQueryString}";

            return $"https://api.ipapi.is/?q={target}{apiKeyQueryString}";
        }

        /// <summary>
        /// Checks if an IP address is likely a public, routable address.
        /// Handles both IPv4 and IPv6. Checks against loopback, private ranges, link-local, etc.
        /// </summary>
        /// <param name="ip">The IPAddress to check.</param>
        /// <returns>True if the IP is considered public, false otherwise.</returns>
        private static bool IsPublicIp(IPAddress ip)
        {
            if (ip == null) return false;

            // Use built-in checks first
            if (IPAddress.IsLoopback(ip)) return false;
            if (ip.IsIPv6LinkLocal) return false;
            if (ip.IsIPv6SiteLocal) return false; // Obsolete but still checkable
            if (ip.IsIPv6Multicast) return false;
            // Note: IsIPv6Teredo might be public in some contexts, but often NAT-traversal related. Treat as non-public for simplicity.
            if (ip.IsIPv6Teredo) return false;
            if (ip.IsIPv6UniqueLocal) return false;


            // Manual IPv4 Private Range Checks (more specific than some built-ins might be)
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                 byte[] bytes = ip.GetAddressBytes();
                 switch (bytes[0])
                 {
                     case 0: // Current network (invalid as source/destination)
                         return false;
                     case 10: // Class A Private
                         return false;
                     case 100 when (bytes[1] >= 64 && bytes[1] <= 127): // Shared Address Space (RFC 6598) - Treat as private/non-public
                         return false;
                     case 127: // Loopback (already covered by IsLoopback)
                         return false;
                     case 169 when bytes[1] == 254: // APIPA Link-local
                         return false;
                     case 172 when (bytes[1] >= 16 && bytes[1] <= 31): // Class B Private
                         return false;
                     case 192 when bytes[1] == 0 && bytes[2] == 0: // Reserved (IETF Protocol Assignments)
                         return false;
                     case 192 when bytes[1] == 0 && bytes[2] == 2: // Test-Net-1 (RFC 5737)
                         return false;
                     case 192 when bytes[1] == 88 && bytes[2] == 99: // 6to4 Relay Anycast (RFC 3068) - Treat as non-public infra
                         return false;
                     case 192 when bytes[1] == 168: // Class C Private
                         return false;
                     case 198 when bytes[1] == 18 || bytes[1] == 19: // Test-Net-2 & 3 (RFC 5737)
                         return false;
                     case 198 when bytes[1] == 51 && bytes[2] == 100: // Documentation (TEST-NET-2 - RFC 5737)
                         return false;
                     case 203 when bytes[1] == 0 && bytes[2] == 113: // Documentation (TEST-NET-3 - RFC 5737)
                         return false;
                     case >= 224 and <= 239: // Multicast (Class D)
                         return false;
                     case >= 240: // Reserved (Class E), Broadcast (255.255.255.255)
                         return false;
                     default:
                         return true; // Assume public if not caught by specific ranges
                 }
            }
            // IPv6 Checks (after built-ins)
            else if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                 // Check for IPv4 mapped addresses (::ffff:x.y.z.w) and check the IPv4 part recursively
                 if (ip.IsIPv4MappedToIPv6)
                 {
                    // Extract the IPv4 part - This is tricky to do directly with GetAddressBytes reliably.
                    // A common way is to convert back to string and parse, or use internal methods if available.
                    // Simplification: If IPAddress thinks it's mapped, let's try converting it.
                    // This might not be the most efficient way.
                    try {
                        byte[] ipv6Bytes = ip.GetAddressBytes();
                        byte[] ipv4Bytes = new byte[4];
                        Buffer.BlockCopy(ipv6Bytes, 12, ipv4Bytes, 0, 4);
                        var ipv4Part = new IPAddress(ipv4Bytes);
                        return IsPublicIp(ipv4Part); // Recursive call
                    } catch {
                        return false; // Error during extraction, treat as non-public
                    }
                 }

                 // Add specific IPv6 Bogons if needed, e.g., Documentation range 2001:db8::/32
                 byte[] v6bytes = ip.GetAddressBytes();
                 if (v6bytes[0] == 0x20 && v6bytes[1] == 0x01 && v6bytes[2] == 0x0d && v6bytes[3] == 0xb8) // 2001:db8::/32
                 {
                    return false;
                 }

                 // Add more specific ranges here if needed (e.g., ::/8, fc00::/7 Unique Local)

                 // If none of the specific non-public checks passed, assume it's public IPv6
                 return true;
            }

            // Unknown address family
            return false;
        }

        private static async Task<IpApiResponse> FetchIpApiResponse(string url, CancellationToken cancellationToken)
        {
            // Check cache first (cache key IS the full URL including API key if present)
            if (TryGetCachedResponse(url, out IpApiResponse cachedResponse))
            {
                Context.API.LogInfo(nameof(Main), $"Cache hit for URL: {url}");
                return cachedResponse;
            }

            // Use the CancellationToken in the HttpClient request
            var responseString = await HttpClient.GetStringAsync(url, cancellationToken);

            if (string.IsNullOrWhiteSpace(responseString))
            {
                 Context.API.LogWarn(nameof(Main), $"API returned empty response for URL: {url}");
                 return null; // Or throw, or return an empty object depending on desired handling
            }

            try
            {
                var apiResponse = JsonSerializer.Deserialize<IpApiResponse>(responseString, JsonSerializerOptions);

                if (apiResponse != null)
                {
                    CacheResponse(url, apiResponse); // Cache the valid response
                }
                else
                {
                     Context.API.LogWarn(nameof(Main), $"Failed to deserialize API response for URL: {url}");
                }
                return apiResponse;
            }
            catch (JsonException jsonEx)
            {
                 Context.API.LogWarn(nameof(Main), $"JSON Deserialization error for URL {url}: {jsonEx.Message}", jsonEx);
                 // Optionally log responseString here (beware of sensitive data if API key included)
                 throw new Exception($"Failed to parse API response. Please check logs. (URL: {url})", jsonEx); // Re-throw with more context
            }
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

        /// <inheritdoc />
        public Control CreateSettingPanel()
        {
            return new SettingsControl(_settings);
        }
    }
}
