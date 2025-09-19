#pragma once

#include "plugins/plugin_interface.hpp"
#include <regex>
#include <unordered_map>
#include <deque>

namespace netlogai::plugins::examples {

class PerformancePlugin : public IPerformancePlugin {
public:
    PerformancePlugin();
    virtual ~PerformancePlugin() = default;

    // INetLogAIPlugin interface
    std::string get_name() const override { return "NetLogAI Performance Plugin"; }
    std::string get_version() const override { return "1.0.0"; }
    std::string get_description() const override { return "Network performance monitoring and analysis"; }
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

    // IPerformancePlugin interface
    PluginResult analyze_bandwidth_usage(const std::vector<LogEntry>& entries) override;
    PluginResult detect_performance_issues(const std::vector<LogEntry>& entries) override;
    PluginResult generate_performance_baseline(const NetworkDevice& device) override;
    std::map<std::string, double> get_performance_metrics(const NetworkDevice& device) override;

    // Additional methods
    std::vector<std::string> get_supported_commands() const override;
    std::map<std::string, std::string> get_configuration_schema() const override;
    std::string get_status() const override;

private:
    struct PerformanceMetric {
        std::string metric_name;
        double value;
        std::string unit;
        std::chrono::system_clock::time_point timestamp;
        std::string device_id;
        std::string interface;
    };

    struct InterfaceStats {
        std::string interface_name;
        uint64_t bytes_in;
        uint64_t bytes_out;
        uint64_t packets_in;
        uint64_t packets_out;
        uint32_t errors_in;
        uint32_t errors_out;
        double utilization_percent;
        std::chrono::system_clock::time_point last_updated;
    };

    struct PerformanceBaseline {
        std::string device_id;
        double avg_cpu_utilization;
        double avg_memory_utilization;
        double avg_interface_utilization;
        uint64_t avg_throughput_bps;
        double avg_latency_ms;
        std::chrono::system_clock::time_point created_at;
        std::chrono::hours baseline_window;
    };

    struct PerformanceAlert {
        std::string alert_id;
        std::string alert_type;
        std::string device_id;
        std::string interface;
        std::string description;
        uint32_t severity;
        double threshold_value;
        double actual_value;
        std::chrono::system_clock::time_point triggered_at;
        bool is_active;
    };

    struct BandwidthSample {
        std::chrono::system_clock::time_point timestamp;
        uint64_t bytes_per_second;
        double utilization_percent;
        std::string interface;
    };

    // Configuration
    bool is_initialized_;
    bool is_running_;
    PluginContext context_;
    std::map<std::string, std::string> config_;

    // Performance tracking
    std::unordered_map<std::string, InterfaceStats> interface_stats_;
    std::unordered_map<std::string, PerformanceBaseline> device_baselines_;
    std::vector<PerformanceAlert> active_alerts_;
    std::deque<PerformanceMetric> metric_history_;

    // Bandwidth analysis
    std::unordered_map<std::string, std::deque<BandwidthSample>> bandwidth_history_;
    size_t max_history_size_;

    // Thresholds and configuration
    double cpu_threshold_;
    double memory_threshold_;
    double interface_utilization_threshold_;
    double latency_threshold_;
    std::chrono::minutes analysis_window_;
    std::chrono::minutes baseline_window_;

    // Helper methods
    void parse_interface_statistics(const LogEntry& entry);
    void parse_cpu_memory_usage(const LogEntry& entry);
    void parse_bandwidth_data(const LogEntry& entry);

    bool is_performance_degraded(const std::string& device_id) const;
    PerformanceAlert create_performance_alert(const std::string& alert_type,
                                             const std::string& device_id,
                                             const std::string& interface,
                                             double threshold,
                                             double actual_value,
                                             const std::string& description);

    // Analysis methods
    std::vector<PerformanceAlert> analyze_cpu_usage(const std::vector<LogEntry>& entries);
    std::vector<PerformanceAlert> analyze_memory_usage(const std::vector<LogEntry>& entries);
    std::vector<PerformanceAlert> analyze_interface_utilization(const std::vector<LogEntry>& entries);
    std::vector<PerformanceAlert> analyze_error_rates(const std::vector<LogEntry>& entries);
    std::vector<PerformanceAlert> analyze_latency_issues(const std::vector<LogEntry>& entries);

    // Baseline management
    void update_device_baseline(const std::string& device_id, const std::vector<PerformanceMetric>& metrics);
    bool is_deviation_from_baseline(const std::string& device_id, const PerformanceMetric& metric) const;

    // Reporting
    std::string generate_performance_report(const std::vector<PerformanceAlert>& alerts);
    std::string format_performance_alert(const PerformanceAlert& alert);
    std::string generate_bandwidth_report(const std::string& device_id);
    std::string generate_trend_analysis();

    // Utility methods
    double calculate_interface_utilization(uint64_t bytes_per_second, uint64_t interface_speed);
    double calculate_average_metric(const std::vector<PerformanceMetric>& metrics, const std::string& metric_name);
    void cleanup_old_metrics();
    void cleanup_old_alerts();
};

} // namespace netlogai::plugins::examples