using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
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
            string originalInput = query.Search ?? "your public IP"; // Keep original input for display
            string apiTarget = originalInput; // Initialize apiTarget
            var fetchedResults = new List<Result>(); // Start fresh list for results

            // --- Initial Placeholder ---
             /*fetchedResults.Add(new Result
             {
                 Title = "Fetching IP details...",
                 SubTitle = $"Looking up: {originalInput}",
                 IcoPath = Icon,
                 Score = 110 // High score to show first
             });*/
             // If you want instant placeholder, return here and update later.
             // await Task.Yield(); // Maybe yield to allow UI update

            try
            {
                // Determine the target IP for the API call
                apiTarget = await GetApiTargetAsync(query.Search, cancellationToken);
                string apiUrl = BuildApiUrl(apiTarget);
                var response = await FetchIpApiResponse(apiUrl, cancellationToken);

                // --- Clear placeholder ---
                fetchedResults.Clear();

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

                // --- 1. Core IP Info ---
                fetchedResults.Add(new Result
                {
                    Title = response.Ip,
                    SubTitle = $"Resolved IP for: {originalInput}",
                    IcoPath = Icon,
                    Action = CreateCopyAction(response.Ip),
                    Score = 100 // Highest score for primary info
                });

                // --- 2. Key Flags ---
                var flagsResults = new List<Result>();
                int flagScore = 98; // Start flags with high score

                // Datacenter Flag
                if (response.IsDatacenter) flagsResults.Add(new Result { Title = "Datacenter IP", SubTitle = "Belongs to a hosting provider/datacenter", IcoPath = Icon, Action = CreateCopyAction("Datacenter IP"), Score = flagScore-- });

                // VPN Flag (handle bool and Vpn object)
                string vpnTitle = null; string vpnSubtitle = null; string vpnCopy = null;
                 if (response.IsVpn is bool vpnBool && vpnBool) { vpnTitle = "VPN Detected"; vpnSubtitle = "IP identified as a VPN"; vpnCopy = "VPN Detected"; }
                 if (response.Vpn != null) { // Override with specific info if available
                     vpnTitle = $"VPN: {response.Vpn.Service ?? "Unknown"}";
                     vpnSubtitle = $"Provider: {response.Vpn.Service ?? "N/A"} ({response.Vpn.Url ?? ""}), Region: {response.Vpn.ExitNodeRegion ?? "N/A"}";
                     vpnCopy = $"VPN: {response.Vpn.Service ?? "N/A"}";
                 }
                 if (vpnTitle != null) flagsResults.Add(new Result { Title = vpnTitle, SubTitle = vpnSubtitle, IcoPath = Icon, Action = CreateCopyAction(vpnCopy), Score = flagScore-- });

                // Proxy Flag
                if (response.IsProxy) flagsResults.Add(new Result { Title = "Proxy Detected", SubTitle = "IP identified as a proxy server", IcoPath = Icon, Action = CreateCopyAction("Proxy Detected"), Score = flagScore-- });

                // TOR Flag
                if (response.IsTor) flagsResults.Add(new Result { Title = "TOR Exit Node", SubTitle = "IP is a TOR exit node", IcoPath = Icon, Action = CreateCopyAction("TOR Exit Node"), Score = flagScore-- });

                // Abuser Flag
                if (response.IsAbuser) flagsResults.Add(new Result { Title = "Abuser Detected", SubTitle = "IP detected on abuse blacklists", IcoPath = Icon, Action = CreateCopyAction("Abuser Detected"), Score = flagScore-- });

                // Crawler Flag (handle object type)
                string crawlerName = null;
                if (response.IsCrawler is string crawlerStr && !string.IsNullOrWhiteSpace(crawlerStr)) { crawlerName = crawlerStr; }
                else if (response.IsCrawler is bool crawlerBool && crawlerBool) { crawlerName = "Generic Bot"; }
                if (crawlerName != null) flagsResults.Add(new Result { Title = $"Crawler: {crawlerName}", SubTitle = "IP belongs to a known crawler/bot", IcoPath = Icon, Action = CreateCopyAction(crawlerName), Score = flagScore-- });

                // Add other flags if desired (lower priority)
                // if (response.IsMobile) flagsResults.Add(new Result { Title = "Mobile IP", ..., Score = flagScore-- });
                // if (response.IsSatellite) flagsResults.Add(new Result { Title = "Satellite IP", ..., Score = flagScore-- });
                // if (response.IsBogon) flagsResults.Add(new Result { Title = "Bogon IP", ..., Score = flagScore-- });

                fetchedResults.AddRange(flagsResults);

                // --- 3. Datacenter Specific Info (If applicable) ---
                if (response.IsDatacenter && response.Datacenter != null)
                {
                    var dcLocationParts = new[] { response.Datacenter.City, response.Datacenter.Region, response.Datacenter.Country };
                    var dcLocation = string.Join(", ", dcLocationParts.Where(s => !string.IsNullOrEmpty(s)));
                    fetchedResults.Add(new Result {
                        Title = $"Datacenter: {response.Datacenter.Datacenter ?? "N/A"}",
                        SubTitle = $"Network: {response.Datacenter.Network ?? "N/A"}" + (string.IsNullOrWhiteSpace(dcLocation) ? "" : $", Location: {dcLocation}"),
                        IcoPath = Icon,
                        Action = CreateCopyAction($"{response.Datacenter.Datacenter ?? "N/A"}"),
                        Score = 90 // Score below flags but still high
                    });
                }

                // --- 4. Location Info ---
                if (response.Location != null)
                {
                    var locationParts = new[] { response.Location.City, response.Location.State, response.Location.Country };
                    var location = string.Join(", ", locationParts.Where(l => !string.IsNullOrEmpty(l)));
                    if (!string.IsNullOrWhiteSpace(location))
                    {
                        fetchedResults.Add(new Result
                        {
                            Title = location,
                            SubTitle = "Approximate Location", // Simplified subtitle
                            IcoPath = Icon,
                            Action = CreateCopyAction(location),
                            Score = 85
                        });
                    }

                    if (!string.IsNullOrWhiteSpace(response.Location.Timezone))
                    {
                        fetchedResults.Add(new Result
                        {
                            Title = response.Location.Timezone,
                            SubTitle = "Timezone" + (!string.IsNullOrWhiteSpace(response.Location.LocalTime) ? $" / Local: {response.Location.LocalTime.Split('+')[0].Split('-')[0]}" : ""), // Simplified local time display
                            IcoPath = Icon,
                            Action = CreateCopyAction(response.Location.Timezone),
                            Score = 80
                        });
                    }
                     // Coordinates link - Lower priority
                     if (response.Location.Latitude != 0 || response.Location.Longitude != 0)
                     {
                         var googleMapsLink = GenerateGoogleMapsLink(response.Location.LatitudeFormatted, response.Location.LongitudeFormatted);
                         fetchedResults.Add(new Result
                         {
                             Title = $"Lat/Lon: {response.Location.LatitudeFormatted}, {response.Location.LongitudeFormatted}",
                             SubTitle = "Click to view on Google Maps",
                             IcoPath = Icon,
                             Action = CreateOpenBrowserAction(googleMapsLink),
                             Score = 70 // Lowest score
                         });
                    }
                }

                // --- 5. ISP / ASN Org Info ---
                if (response.Asn != null && !string.IsNullOrWhiteSpace(response.Asn.Org))
                {
                    fetchedResults.Add(new Result
                    {
                        Title = response.Asn.Org,
                        // Display ASN Type if different from Datacenter type or if not datacenter
                        SubTitle = $"ISP / Org (AS{response.Asn.Asn?.ToString() ?? "?"})" +
                                   ((response.Asn.Type != null && (!response.IsDatacenter || response.Asn.Type != "hosting")) ? $" - Type: {response.Asn.Type}" : ""),
                        IcoPath = Icon,
                        Action = CreateCopyAction($"{response.Asn.Org} (AS{response.Asn.Asn?.ToString() ?? "?"})"),
                        Score = 84 // Below location, above timezone
                    });
                }
            }
            catch (OperationCanceledException)
            {
                 fetchedResults.Clear();
                 fetchedResults.Add(new Result { Title = "Query cancelled", SubTitle = $"Lookup for: {originalInput}", IcoPath = Icon });
            }
            catch (Exception ex)
            {
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

        private static async Task<string> GetApiTargetAsync(string userInput, CancellationToken cancellationToken)
        {
            string target = userInput?.Trim() ?? string.Empty;

            // --- Input Cleaning (remains the same) ---
            if (Uri.TryCreate(target, UriKind.Absolute, out var uri) && (uri.Scheme == "http" || uri.Scheme == "https://"))
            {
                target = uri.DnsSafeHost;
            }
            else
            {
                if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                    target = target.Substring(7);
                else if (target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                    target = target.Substring(8);

                target = target.TrimEnd('/');
                int pathSeparatorIndex = target.IndexOf('/');
                if (pathSeparatorIndex >= 0)
                {
                    target = target.Substring(0, pathSeparatorIndex);
                }
            }
            int portSeparatorIndex = target.LastIndexOf(':');
            if (portSeparatorIndex > 0 && target.IndexOf(']') < portSeparatorIndex)
            {
                 target = target.Substring(0, portSeparatorIndex);
            }

            // --- Target Determination ---
            if (string.IsNullOrEmpty(target))
            {
                // Case 1: Empty input -> Get own public IP
                // Use the GetPublicIpAddressAsync defined earlier
                return await GetPublicIpAddressAsync() ?? throw new Exception("Failed to determine own public IP and input was empty.");
            }

            if (IPAddress.TryParse(target, out var ipAddress))
            {
                // Case 2: Input is an IP address
                // No need to check if public here, let ipapi.is handle all IP types directly
                return ipAddress.ToString();
            }
            else
            {
                // Case 3: Input is not an IP address -> Assume domain/hostname and perform DNS lookup
                try
                {
                    // Perform DNS lookup asynchronously
                    IPAddress[] addresses = await Dns.GetHostAddressesAsync(target, cancellationToken);

                    if (addresses == null || addresses.Length == 0)
                    {
                        throw new Exception($"No IP addresses found for host: {target}");
                    }

                    // --- Select the best IP address ---
                    // Prioritize Public IPv4, then Public IPv6, then first available.
                    IPAddress selectedIp = addresses.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork && IsPublicIp(ip)) // Public IPv4
                                        ?? addresses.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetworkV6 && IsPublicIp(ip)) // Public IPv6
                                        ?? addresses.FirstOrDefault(IsPublicIp) // Any Public IP
                                        ?? addresses.First(); // Fallback to the very first IP found

                    return selectedIp.ToString();
                }
                catch (SocketException ex)
                {
                    // Common exception for DNS resolution failures (host not found, DNS server error)
                    throw new Exception($"Could not resolve host: {target}. Check the name or your network connection. (Error: {ex.SocketErrorCode})");
                }
                catch (OperationCanceledException)
                {
                     // Rethrow cancellation if DNS lookup itself was cancelled
                     throw;
                }
                catch (Exception ex) // Catch other potential errors during DNS lookup
                {
                    throw new Exception($"An unexpected error occurred while resolving host: {target}.");
                }
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
                return cachedResponse;
            }

            // Use the CancellationToken in the HttpClient request
            var responseString = await HttpClient.GetStringAsync(url, cancellationToken);

            if (string.IsNullOrWhiteSpace(responseString))
            {
                 return null; // Or throw, or return an empty object depending on desired handling
            }

            try
            {
                var apiResponse = JsonSerializer.Deserialize<IpApiResponse>(responseString, JsonSerializerOptions);

                if (apiResponse != null)
                {
                    CacheResponse(url, apiResponse); // Cache the valid response
                }
                return apiResponse;
            }
            catch (JsonException jsonEx)
            {
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
