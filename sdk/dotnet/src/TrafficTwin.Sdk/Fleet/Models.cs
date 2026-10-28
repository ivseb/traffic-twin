using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace TrafficTwin.Sdk.Fleet;

internal sealed class SigningKey
{
    [JsonPropertyName("kid")] public string Kid { get; set; } = "";
    [JsonPropertyName("alg")] public string Alg { get; set; } = "Ed25519";
    [JsonPropertyName("public_key")] public string PublicKey { get; set; } = "";
}

/// <summary>The enrollment response (api/fleet-api.v1.openapi.yaml#Enrollment) plus local bookkeeping.</summary>
internal sealed class Enrollment
{
    [JsonPropertyName("source_id")] public string SourceId { get; set; } = "";
    [JsonPropertyName("group")] public string Group { get; set; } = "";
    [JsonPropertyName("service_name")] public string ServiceName { get; set; } = "";
    [JsonPropertyName("client_cert")] public string ClientCert { get; set; } = "";
    [JsonPropertyName("ca_chain")] public string CaChain { get; set; } = "";
    [JsonPropertyName("not_after")] public string? NotAfter { get; set; }
    [JsonPropertyName("policy_signing_keys")] public List<SigningKey> PolicySigningKeys { get; set; } = new();
    [JsonPropertyName("intake_url")] public string IntakeUrl { get; set; } = "";
    [JsonPropertyName("fleet_url")] public string FleetUrl { get; set; } = "";
    [JsonPropertyName("policy_max_age_s")] public long PolicyMaxAgeS { get; set; } = 86400;
    [JsonPropertyName("heartbeat_interval_s")] public long HeartbeatIntervalS { get; set; } = 30;
    [JsonPropertyName("policy_poll_interval_s")] public long PolicyPollIntervalS { get; set; } = 60;
    [JsonPropertyName("enroll_url")] public string EnrollUrl { get; set; } = "";
    [JsonPropertyName("pin")] public string Pin { get; set; } = "";
}

/// <summary>State that must survive a restart: kill switch, revocation, policy sequence floor, signing key changes.</summary>
internal sealed class PersistedState
{
    [JsonPropertyName("kill")] public bool Kill { get; set; }
    [JsonPropertyName("revoked")] public bool Revoked { get; set; }
    [JsonPropertyName("min_issued_seq")] public long MinIssuedSeq { get; set; }
    [JsonPropertyName("last_issued_seq")] public long LastIssuedSeq { get; set; }
    [JsonPropertyName("revoked_kids")] public List<string> RevokedKids { get; set; } = new();
    [JsonPropertyName("added_keys")] public List<SigningKey> AddedKeys { get; set; } = new();
}
