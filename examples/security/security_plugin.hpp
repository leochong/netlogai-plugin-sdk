#pragma once

#include "plugins/plugin_interface.hpp"
#include <regex>
#include <unordered_map>
#include <unordered_set>

namespace netlogai::plugins::examples {

class SecurityPlugin : public ISecurityPlugin {
public:
    SecurityPlugin();
    virtual ~SecurityPlugin() = default;

    // INetLogAIPlugin interface
    std::string get_name() const override { return "NetLogAI Security Plugin"; }
    std::string get_version() const override { return "1.0.0"; }
    std::string get_description() const override { return "Network security analysis and threat detection"; }
    std::string get_author() const override { return "NetLogAI Team"; }
    std::string get_api_version() const override { return NETLOGAI_PLUGIN_API_VERSION; }
    PluginCapability get_capabilities() const override;

    bool initialize(const PluginContext& context) override;
    bool configure(const std::map<std::string, std::string>& config) override;
    bool start() override;
    bool stop() override;
    void cleanup() override;

    PluginResult process_log_entries(const std::vector<LogEntry>& entries) override;
    PluginResult analyze_device(const NetworkDevice& device) override;
    PluginResult execute_command(const std::string& command,
                               const std::map<std::string, std::string>& parameters) override;

    // Real-time processing
    bool supports_real_time() const override { return true; }
    PluginResult process_real_time_entry(const LogEntry& entry) override;

    // ISecurityPlugin interface
    PluginResult detect_threats(const std::vector<LogEntry>& entries) override;
    PluginResult analyze_authentication_failures(const std::vector<LogEntry>& entries) override;
    PluginResult scan_for_vulnerabilities(const NetworkDevice& device) override;
    std::vector<std::string> get_threat_signatures() const override;

    // Additional methods
    std::vector<std::string> get_supported_commands() const override;
    std::map<std::string, std::string> get_configuration_schema() const override;
    std::string get_status() const override;

private:
    struct ThreatSignature {
        std::string name;
        std::string description;
        std::regex pattern;
        uint32_t severity;
        std::string category;
        std::vector<std::string> indicators;
    };

    struct SecurityEvent {
        std::string event_id;
        std::chrono::system_clock::time_point timestamp;
        std::string threat_type;
        std::string source_device;
        std::string source_ip;
        std::string target_ip;
        uint32_t severity;
        std::string description;
        std::vector<std::string> evidence;
    };

    struct AuthFailurePattern {
        std::string source_ip;
        std::string username;
        uint32_t failure_count;
        std::chrono::system_clock::time_point first_attempt;
        std::chrono::system_clock::time_point last_attempt;
        bool is_brute_force;
    };

    // Configuration
    bool is_initialized_;
    bool is_running_;
    PluginContext context_;
    std::map<std::string, std::string> config_;

    // Threat detection
    std::vector<ThreatSignature> threat_signatures_;
    std::vector<SecurityEvent> detected_events_;
    std::unordered_map<std::string, AuthFailurePattern> auth_failures_;

    // Thresholds and limits
    uint32_t brute_force_threshold_;
    uint32_t suspicious_activity_threshold_;
    std::chrono::minutes auth_failure_window_;

    // IP reputation and blacklists
    std::unordered_set<std::string> known_malicious_ips_;
    std::unordered_set<std::string> suspicious_patterns_;

    // Helper methods
    void load_threat_signatures();
    void load_malicious_ip_database();
    bool is_suspicious_ip(const std::string& ip) const;
    bool is_brute_force_attack(const std::string& source_ip, const std::string& username);
    SecurityEvent create_security_event(const std::string& threat_type,
                                       const LogEntry& entry,
                                       uint32_t severity,
                                       const std::string& description);

    // Analysis methods
    std::vector<SecurityEvent> analyze_login_attempts(const std::vector<LogEntry>& entries);
    std::vector<SecurityEvent> analyze_network_anomalies(const std::vector<LogEntry>& entries);
    std::vector<SecurityEvent> analyze_privilege_escalation(const std::vector<LogEntry>& entries);
    std::vector<SecurityEvent> analyze_data_exfiltration(const std::vector<LogEntry>& entries);

    // Reporting
    std::string generate_security_report(const std::vector<SecurityEvent>& events);
    std::string format_security_event(const SecurityEvent& event);
    uint32_t calculate_risk_score(const std::vector<SecurityEvent>& events);
};

} // namespace netlogai::plugins::examples