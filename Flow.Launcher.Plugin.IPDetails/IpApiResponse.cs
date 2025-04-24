using System;
using System.Collections.Generic; // Needed
using System.Globalization;
using System.Text.Json.Serialization;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace Flow.Launcher.Plugin.IPDetails;

// --- CachedIpApiResponse (Usually Fine) ---
public class CachedIpApiResponse
{
    public DateTime Timestamp { get; set; }
    public IpApiResponse Response { get; set; }
}

// --- IpApiResponse (Updated) ---
public class IpApiResponse
{
    [JsonPropertyName("ip")] public string Ip { get; set; }
    [JsonPropertyName("rir")] public string Rir { get; set; }
    [JsonPropertyName("is_bogon")] public bool IsBogon { get; set; }
    [JsonPropertyName("is_mobile")] public bool IsMobile { get; set; }
    [JsonPropertyName("is_satellite")] public bool IsSatellite { get; set; } // Added
    [JsonPropertyName("is_crawler")] public object IsCrawler { get; set; } // Changed to object
    [JsonPropertyName("is_datacenter")] public bool IsDatacenter { get; set; }
    [JsonPropertyName("is_tor")] public bool IsTor { get; set; }
    [JsonPropertyName("is_proxy")] public bool IsProxy { get; set; }
    [JsonConverter(typeof(IsVpnConverter))]
    [JsonPropertyName("is_vpn")] public object IsVpn { get; set; } // Keep as object
    [JsonPropertyName("is_abuser")] public bool IsAbuser { get; set; }
    [JsonPropertyName("elapsed_ms")] public double ElapsedMs { get; set; }

    // Added Objects
    [JsonPropertyName("vpn")] public VpnInfo Vpn { get; set; } // Added
    [JsonPropertyName("datacenter")] public DatacenterInfo Datacenter { get; set; } // Added

    [JsonPropertyName("company")] public CompanyInfo Company { get; set; }
    [JsonPropertyName("abuse")] public AbuseInfo Abuse { get; set; }
    [JsonPropertyName("asn")] public AsnInfo Asn { get; set; }
    [JsonPropertyName("location")] public LocationInfo Location { get; set; }
}

// --- NEW Class: VpnInfo ---
public class VpnInfo
{
    [JsonPropertyName("service")] public string Service { get; set; }
    [JsonPropertyName("url")] public string Url { get; set; }
    [JsonPropertyName("type")] public string Type { get; set; }
    [JsonPropertyName("last_seen")] public long? LastSeen { get; set; }
    [JsonPropertyName("last_seen_str")] public string LastSeenStr { get; set; }
    [JsonPropertyName("exit_node_region")] public string ExitNodeRegion { get; set; }
    [JsonPropertyName("country_code")] public string CountryCode { get; set; }
    [JsonPropertyName("city_name")] public string CityName { get; set; }
    [JsonPropertyName("latitude")] public double? Latitude { get; set; }
    [JsonPropertyName("longitude")] public double? Longitude { get; set; }
}

// --- NEW Class: DatacenterInfo ---
public class DatacenterInfo
{
    [JsonPropertyName("datacenter")] public string Datacenter { get; set; }
    [JsonPropertyName("domain")] public string Domain { get; set; }
    [JsonPropertyName("network")] public string Network { get; set; }
    [JsonPropertyName("region")] public string Region { get; set; }
    [JsonPropertyName("service")] public string Service { get; set; }
    [JsonPropertyName("network_border_group")] public string NetworkBorderGroup { get; set; }
    [JsonPropertyName("code")] public string Code { get; set; }
    [JsonPropertyName("city")] public string City { get; set; }
    [JsonPropertyName("state")] public string State { get; set; }
    [JsonPropertyName("country")] public string Country { get; set; }
    [JsonPropertyName("name")] public string Name { get; set; }
}

// --- CompanyInfo (Updated) ---
public class CompanyInfo
{
    [JsonPropertyName("name")] public string Name { get; set; }
    [JsonPropertyName("abuser_score")] public string AbuserScore { get; set; }
    [JsonPropertyName("domain")] public string Domain { get; set; }
    [JsonPropertyName("type")] public string Type { get; set; }
    [JsonPropertyName("network")] public string Network { get; set; }
    [JsonPropertyName("whois")] public string Whois { get; set; }
}

// --- AbuseInfo (Updated) ---
public class AbuseInfo
{
    [JsonPropertyName("name")] public string Name { get; set; }
    [JsonPropertyName("address")] public string Address { get; set; }
    [JsonPropertyName("country")] public string Country { get; set; } // Added
    [JsonPropertyName("email")] public string Email { get; set; }
    [JsonPropertyName("phone")] public string Phone { get; set; }
}

// --- AsnInfo (Updated) ---
public class AsnInfo
{
    [JsonPropertyName("asn")] public int? Asn { get; set; } // Made nullable
    [JsonPropertyName("abuser_score")] public string AbuserScore { get; set; }
    [JsonPropertyName("route")] public string Route { get; set; }
    [JsonPropertyName("descr")] public string Descr { get; set; }
    [JsonPropertyName("country")] public string Country { get; set; }
    [JsonPropertyName("active")] public bool Active { get; set; }
    [JsonPropertyName("org")] public string Org { get; set; }
    [JsonPropertyName("domain")] public string Domain { get; set; }
    [JsonPropertyName("abuse")] public string Abuse { get; set; } // Email
    [JsonPropertyName("type")] public string Type { get; set; }
    [JsonPropertyName("created")] public string Created { get; set; } // Added
    [JsonPropertyName("updated")] public string Updated { get; set; }
    [JsonPropertyName("rir")] public string Rir { get; set; }
    [JsonPropertyName("whois")] public string Whois { get; set; }
}

// --- LocationInfo (Updated) ---
public class LocationInfo
{
    [JsonPropertyName("is_eu_member")] public bool IsEuMember { get; set; } // Added
    [JsonPropertyName("calling_code")] public string CallingCode { get; set; } // Added
    [JsonPropertyName("currency_code")] public string CurrencyCode { get; set; } // Added
    [JsonPropertyName("continent")] public string Continent { get; set; }
    [JsonPropertyName("country")] public string Country { get; set; }
    [JsonPropertyName("country_code")] public string CountryCode { get; set; }
    [JsonPropertyName("state")] public string State { get; set; }
    [JsonPropertyName("city")] public string City { get; set; }
    [JsonPropertyName("latitude")] public double Latitude { get; set; }
    public string LatitudeFormatted => Latitude.ToString("G", CultureInfo.InvariantCulture);
    [JsonPropertyName("longitude")] public double Longitude { get; set; }
    public string LongitudeFormatted => Longitude.ToString("G", CultureInfo.InvariantCulture);
    [JsonPropertyName("zip")] public string Zip { get; set; }
    [JsonPropertyName("timezone")] public string Timezone { get; set; }
    [JsonPropertyName("local_time")] public string LocalTime { get; set; }
    [JsonPropertyName("local_time_unix")] public long LocalTimeUnix { get; set; }
    [JsonPropertyName("is_dst")] public bool IsDst { get; set; }
    [JsonPropertyName("accuracy")] public int? Accuracy { get; set; } // Made nullable
    // [JsonPropertyName("other")] public List<string> Other { get; set; } // Optional
}

// --- IsVpnConverter (Ensure it exists and handles bool/string/null) ---
public class IsVpnConverter : JsonConverter<object>
{
     public override object Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
     {
         switch (reader.TokenType)
         {
             case JsonTokenType.True: return true;
             case JsonTokenType.False: return false;
             case JsonTokenType.String: return reader.GetString(); // Can be bool string or other
             case JsonTokenType.Null: return null;
             default:
                 reader.Skip();
                 return null;
         }
     }

     public override void Write(Utf8JsonWriter writer, object value, JsonSerializerOptions options)
     {
         JsonSerializer.Serialize(writer, value, value?.GetType() ?? typeof(object), options);
     }
}
