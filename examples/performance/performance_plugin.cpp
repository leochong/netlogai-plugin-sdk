#include "performance_plugin.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>

namespace netlogai::plugins::examples {

PerformancePlugin::PerformancePlugin()
    : is_initialized_(false), is_running_(false),
      max_history_size_(1000),
      cpu_threshold_(80.0), memory_threshold_(85.0),
      interface_utilization_threshold_(90.0), latency_threshold_(100.0),
      analysis_window_(std::chrono::minutes(30)),
      baseline_window_(std::chrono::minutes(60 * 24)) {} // 24 hours

PluginCapability PerformancePlugin::get_capabilities() const {
    return PluginCapability::LOG_ANALYSIS |
           PluginCapability::REAL_TIME_MONITORING |
           PluginCapability::ALERTING |
           PluginCapability::CONFIGURATION;
}

bool PerformancePlugin::initialize(const PluginContext& context) {
    if (is_initialized_) {
        return true;
    }

    context_ = context;
    is_initialized_ = true;
    return true;
}

bool PerformancePlugin::configure(const std::map<std::string, std::string>& config) {
    config_ = config;

    // Parse configuration values
    auto cpu_it = config.find("cpu_threshold");
    if (cpu_it != config.end()) {
        cpu_threshold_ = std::stod(cpu_it->second);
    }

    auto memory_it = config.find("memory_threshold");
    if (memory_it != config.end()) {
        memory_threshold_ = std::stod(memory_it->second);
    }

    auto interface_it = config.find("interface_utilization_threshold");
    if (interface_it != config.end()) {
        interface_utilization_threshold_ = std::stod(interface_it->second);
    }

    auto latency_it = config.find("latency_threshold");
    if (latency_it != config.end()) {
        latency_threshold_ = std::stod(latency_it->second);
    }

    auto window_it = config.find("analysis_window_minutes");
    if (window_it != config.end()) {
        analysis_window_ = std::chrono::minutes(std::stoi(window_it->second));
    }

    return true;
}

bool PerformancePlugin::start() {
    if (!is_initialized_) {
        return false;
    }

    is_running_ = true;
    return true;
}

bool PerformancePlugin::stop() {
    is_running_ = false;
    return true;
}

void PerformancePlugin::cleanup() {
    interface_stats_.clear();
    device_baselines_.clear();
    active_alerts_.clear();
    metric_history_.clear();
    bandwidth_history_.clear();
    is_running_ = false;
    is_initialized_ = false;
}

PluginResult PerformancePlugin::process_log_entries(const std::vector<LogEntry>& entries) {
    if (!is_running_) {
        return {false, "Performance plugin not running", {}, {}, {}, {}, 0};
    }

    auto start_time = std::chrono::steady_clock::now();

    // Parse performance data from log entries
    for (const auto& entry : entries) {
        parse_interface_statistics(entry);
        parse_cpu_memory_usage(entry);
        parse_bandwidth_data(entry);
    }

    // Perform performance analysis
    auto bandwidth_result = analyze_bandwidth_usage(entries);
    auto performance_result = detect_performance_issues(entries);

    // Clean up old data
    cleanup_old_metrics();
    cleanup_old_alerts();

    auto end_time = std::chrono::steady_clock::now();
    auto execution_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Prepare result
    std::map<std::string, std::string> result_data;
    result_data["interfaces_monitored"] = std::to_string(interface_stats_.size());
    result_data["active_alerts"] = std::to_string(active_alerts_.size());
    result_data["metrics_collected"] = std::to_string(metric_history_.size());

    std::string summary = generate_performance_report(active_alerts_);

    return {
        true,
        summary,
        result_data,
        {},  // warnings
        {},  // errors
        execution_time,
        0    // memory usage
    };
}

PluginResult PerformancePlugin::analyze_bandwidth_usage(const std::vector<LogEntry>& entries) {
    std::vector<PerformanceAlert> bandwidth_alerts;

    // Analyze bandwidth patterns and utilization
    for (const auto& [device_interface, samples] : bandwidth_history_) {
        if (samples.empty()) continue;

        // Calculate average utilization over recent samples
        double total_utilization = 0.0;
        int recent_samples = 0;
        auto cutoff_time = std::chrono::system_clock::now() - analysis_window_;

        for (const auto& sample : samples) {
            if (sample.timestamp >= cutoff_time) {
                total_utilization += sample.utilization_percent;
                recent_samples++;
            }
        }

        if (recent_samples > 0) {
            double avg_utilization = total_utilization / recent_samples;

            if (avg_utilization > interface_utilization_threshold_) {
                size_t separator_pos = device_interface.find(':');
                std::string device_id = device_interface.substr(0, separator_pos);
                std::string interface = (separator_pos != std::string::npos) ?
                    device_interface.substr(separator_pos + 1) : "";

                PerformanceAlert alert = create_performance_alert(
                    "high_bandwidth_utilization",
                    device_id,
                    interface,
                    interface_utilization_threshold_,
                    avg_utilization,
                    "Interface bandwidth utilization exceeded threshold"
                );
                bandwidth_alerts.push_back(alert);
            }
        }
    }

    // Add alerts to active alerts list
    active_alerts_.insert(active_alerts_.end(), bandwidth_alerts.begin(), bandwidth_alerts.end());

    std::map<std::string, std::string> result_data;
    result_data["bandwidth_alerts"] = std::to_string(bandwidth_alerts.size());

    return {
        true,
        "Analyzed bandwidth usage for " + std::to_string(bandwidth_history_.size()) + " interfaces",
        result_data,
        {}, {}, {}, 0
    };
}

PluginResult PerformancePlugin::detect_performance_issues(const std::vector<LogEntry>& entries) {
    std::vector<PerformanceAlert> all_alerts;

    // Perform various performance analyses
    auto cpu_alerts = analyze_cpu_usage(entries);
    auto memory_alerts = analyze_memory_usage(entries);
    auto interface_alerts = analyze_interface_utilization(entries);
    auto error_alerts = analyze_error_rates(entries);
    auto latency_alerts = analyze_latency_issues(entries);

    // Combine all alerts
    all_alerts.insert(all_alerts.end(), cpu_alerts.begin(), cpu_alerts.end());
    all_alerts.insert(all_alerts.end(), memory_alerts.begin(), memory_alerts.end());
    all_alerts.insert(all_alerts.end(), interface_alerts.begin(), interface_alerts.end());
    all_alerts.insert(all_alerts.end(), error_alerts.begin(), error_alerts.end());
    all_alerts.insert(all_alerts.end(), latency_alerts.begin(), latency_alerts.end());

    // Add to active alerts
    active_alerts_.insert(active_alerts_.end(), all_alerts.begin(), all_alerts.end());

    std::map<std::string, std::string> result_data;
    result_data["performance_alerts"] = std::to_string(all_alerts.size());
    result_data["cpu_alerts"] = std::to_string(cpu_alerts.size());
    result_data["memory_alerts"] = std::to_string(memory_alerts.size());
    result_data["interface_alerts"] = std::to_string(interface_alerts.size());

    return {
        true,
        "Detected " + std::to_string(all_alerts.size()) + " performance issues",
        result_data,
        {}, {}, {}, 0
    };
}

void PerformancePlugin::parse_interface_statistics(const LogEntry& entry) {
    // Parse interface statistics from log entries
    // Example patterns for Cisco devices
    std::regex interface_stats_regex(
        R"(Interface\s+([A-Za-z0-9\/]+).*input\s+rate\s+(\d+).*output\s+rate\s+(\d+))",
        std::regex_constants::icase
    );

    std::regex utilization_regex(
        R"(([A-Za-z0-9\/]+).*utilization:\s+(\d+(?:\.\d+)?)%)",
        std::regex_constants::icase
    );

    std::smatch match;

    // Parse interface statistics
    if (std::regex_search(entry.message, match, interface_stats_regex)) {
        std::string interface_name = match[1];
        uint64_t input_rate = std::stoull(match[2]);
        uint64_t output_rate = std::stoull(match[3]);

        std::string key = entry.device_name + ":" + interface_name;
        InterfaceStats& stats = interface_stats_[key];
        stats.interface_name = interface_name;
        stats.bytes_in += input_rate;
        stats.bytes_out += output_rate;
        stats.last_updated = entry.timestamp;

        // Store bandwidth sample
        BandwidthSample sample;
        sample.timestamp = entry.timestamp;
        sample.bytes_per_second = input_rate + output_rate;
        sample.interface = interface_name;
        sample.utilization_percent = calculate_interface_utilization(sample.bytes_per_second, 1000000000); // Assume 1Gbps

        bandwidth_history_[key].push_back(sample);
        if (bandwidth_history_[key].size() > max_history_size_) {
            bandwidth_history_[key].pop_front();
        }
    }

    // Parse utilization percentages
    if (std::regex_search(entry.message, match, utilization_regex)) {
        std::string interface_name = match[1];
        double utilization = std::stod(match[2]);

        PerformanceMetric metric;
        metric.metric_name = "interface_utilization";
        metric.value = utilization;
        metric.unit = "percent";
        metric.timestamp = entry.timestamp;
        metric.device_id = entry.device_name;
        metric.interface = interface_name;

        metric_history_.push_back(metric);
        if (metric_history_.size() > max_history_size_) {
            metric_history_.pop_front();
        }
    }
}

void PerformancePlugin::parse_cpu_memory_usage(const LogEntry& entry) {
    // Parse CPU and memory usage patterns
    std::regex cpu_regex(R"(CPU\s+utilization:\s+(\d+(?:\.\d+)?)%)", std::regex_constants::icase);
    std::regex memory_regex(R"(Memory\s+utilization:\s+(\d+(?:\.\d+)?)%)", std::regex_constants::icase);

    std::smatch match;

    if (std::regex_search(entry.message, match, cpu_regex)) {
        double cpu_usage = std::stod(match[1]);

        PerformanceMetric metric;
        metric.metric_name = "cpu_utilization";
        metric.value = cpu_usage;
        metric.unit = "percent";
        metric.timestamp = entry.timestamp;
        metric.device_id = entry.device_name;

        metric_history_.push_back(metric);
    }

    if (std::regex_search(entry.message, match, memory_regex)) {
        double memory_usage = std::stod(match[1]);

        PerformanceMetric metric;
        metric.metric_name = "memory_utilization";
        metric.value = memory_usage;
        metric.unit = "percent";
        metric.timestamp = entry.timestamp;
        metric.device_id = entry.device_name;

        metric_history_.push_back(metric);
    }
}

void PerformancePlugin::parse_bandwidth_data(const LogEntry& entry) {
    // Parse additional bandwidth and throughput data
    std::regex throughput_regex(
        R"(throughput:\s+(\d+(?:\.\d+)?)\s+(bps|kbps|mbps|gbps))",
        std::regex_constants::icase
    );

    std::smatch match;
    if (std::regex_search(entry.message, match, throughput_regex)) {
        double value = std::stod(match[1]);
        std::string unit = match[2];

        // Convert to bits per second
        uint64_t bps = static_cast<uint64_t>(value);
        if (unit == "kbps") bps *= 1000;
        else if (unit == "mbps") bps *= 1000000;
        else if (unit == "gbps") bps *= 1000000000;

        PerformanceMetric metric;
        metric.metric_name = "throughput";
        metric.value = static_cast<double>(bps);
        metric.unit = "bps";
        metric.timestamp = entry.timestamp;
        metric.device_id = entry.device_name;

        metric_history_.push_back(metric);
    }
}

std::vector<PerformancePlugin::PerformanceAlert> PerformancePlugin::analyze_cpu_usage(
    const std::vector<LogEntry>& entries) {

    std::vector<PerformanceAlert> alerts;

    // Find recent CPU metrics
    auto cutoff_time = std::chrono::system_clock::now() - analysis_window_;
    std::unordered_map<std::string, std::vector<double>> device_cpu_values;

    for (const auto& metric : metric_history_) {
        if (metric.metric_name == "cpu_utilization" && metric.timestamp >= cutoff_time) {
            device_cpu_values[metric.device_id].push_back(metric.value);
        }
    }

    // Analyze CPU usage per device
    for (const auto& [device_id, values] : device_cpu_values) {
        if (values.empty()) continue;

        double avg_cpu = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
        double max_cpu = *std::max_element(values.begin(), values.end());

        if (avg_cpu > cpu_threshold_ || max_cpu > 95.0) {
            PerformanceAlert alert = create_performance_alert(
                "high_cpu_usage",
                device_id,
                "",
                cpu_threshold_,
                std::max(avg_cpu, max_cpu),
                "CPU utilization exceeded threshold (avg: " + std::to_string(avg_cpu) +
                "%, max: " + std::to_string(max_cpu) + "%)"
            );
            alerts.push_back(alert);
        }
    }

    return alerts;
}

std::vector<PerformancePlugin::PerformanceAlert> PerformancePlugin::analyze_memory_usage(
    const std::vector<LogEntry>& entries) {

    std::vector<PerformanceAlert> alerts;

    // Similar analysis for memory usage
    auto cutoff_time = std::chrono::system_clock::now() - analysis_window_;
    std::unordered_map<std::string, std::vector<double>> device_memory_values;

    for (const auto& metric : metric_history_) {
        if (metric.metric_name == "memory_utilization" && metric.timestamp >= cutoff_time) {
            device_memory_values[metric.device_id].push_back(metric.value);
        }
    }

    for (const auto& [device_id, values] : device_memory_values) {
        if (values.empty()) continue;

        double avg_memory = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
        double max_memory = *std::max_element(values.begin(), values.end());

        if (avg_memory > memory_threshold_ || max_memory > 95.0) {
            PerformanceAlert alert = create_performance_alert(
                "high_memory_usage",
                device_id,
                "",
                memory_threshold_,
                std::max(avg_memory, max_memory),
                "Memory utilization exceeded threshold (avg: " + std::to_string(avg_memory) +
                "%, max: " + std::to_string(max_memory) + "%)"
            );
            alerts.push_back(alert);
        }
    }

    return alerts;
}

std::vector<PerformancePlugin::PerformanceAlert> PerformancePlugin::analyze_interface_utilization(
    const std::vector<LogEntry>& entries) {

    std::vector<PerformanceAlert> alerts;

    // Analyze interface utilization from stored metrics
    auto cutoff_time = std::chrono::system_clock::now() - analysis_window_;

    for (const auto& [device_interface, stats] : interface_stats_) {
        if (stats.last_updated < cutoff_time) continue;

        if (stats.utilization_percent > interface_utilization_threshold_) {
            size_t separator_pos = device_interface.find(':');
            std::string device_id = device_interface.substr(0, separator_pos);
            std::string interface = (separator_pos != std::string::npos) ?
                device_interface.substr(separator_pos + 1) : "";

            PerformanceAlert alert = create_performance_alert(
                "high_interface_utilization",
                device_id,
                interface,
                interface_utilization_threshold_,
                stats.utilization_percent,
                "Interface " + interface + " utilization exceeded threshold"
            );
            alerts.push_back(alert);
        }
    }

    return alerts;
}

std::vector<PerformancePlugin::PerformanceAlert> PerformancePlugin::analyze_error_rates(
    const std::vector<LogEntry>& entries) {

    std::vector<PerformanceAlert> alerts;

    // Look for error patterns in logs
    std::regex error_rate_regex(R"(([A-Za-z0-9\/]+).*error.*rate:\s+(\d+(?:\.\d+)?))", std::regex_constants::icase);

    for (const auto& entry : entries) {
        std::smatch match;
        if (std::regex_search(entry.message, match, error_rate_regex)) {
            std::string interface = match[1];
            double error_rate = std::stod(match[2]);

            if (error_rate > 1.0) { // More than 1% error rate
                PerformanceAlert alert = create_performance_alert(
                    "high_error_rate",
                    entry.device_name,
                    interface,
                    1.0,
                    error_rate,
                    "High error rate detected on interface " + interface
                );
                alerts.push_back(alert);
            }
        }
    }

    return alerts;
}

std::vector<PerformancePlugin::PerformanceAlert> PerformancePlugin::analyze_latency_issues(
    const std::vector<LogEntry>& entries) {

    std::vector<PerformanceAlert> alerts;

    // Look for latency-related messages
    std::regex latency_regex(R"(latency:\s+(\d+(?:\.\d+)?)\s*ms)", std::regex_constants::icase);
    std::regex delay_regex(R"(delay:\s+(\d+(?:\.\d+)?)\s*ms)", std::regex_constants::icase);

    for (const auto& entry : entries) {
        std::smatch match;
        double latency_value = 0.0;

        if (std::regex_search(entry.message, match, latency_regex)) {
            latency_value = std::stod(match[1]);
        } else if (std::regex_search(entry.message, match, delay_regex)) {
            latency_value = std::stod(match[1]);
        }

        if (latency_value > latency_threshold_) {
            PerformanceAlert alert = create_performance_alert(
                "high_latency",
                entry.device_name,
                "",
                latency_threshold_,
                latency_value,
                "High latency detected: " + std::to_string(latency_value) + "ms"
            );
            alerts.push_back(alert);
        }
    }

    return alerts;
}

PerformancePlugin::PerformanceAlert PerformancePlugin::create_performance_alert(
    const std::string& alert_type,
    const std::string& device_id,
    const std::string& interface,
    double threshold,
    double actual_value,
    const std::string& description) {

    PerformanceAlert alert;
    alert.alert_id = "perf_" + std::to_string(std::hash<std::string>{}(device_id + alert_type + interface));
    alert.alert_type = alert_type;
    alert.device_id = device_id;
    alert.interface = interface;
    alert.description = description;
    alert.threshold_value = threshold;
    alert.actual_value = actual_value;
    alert.triggered_at = std::chrono::system_clock::now();
    alert.is_active = true;

    // Determine severity based on how much the threshold was exceeded
    double excess_ratio = actual_value / threshold;
    if (excess_ratio >= 2.0) {
        alert.severity = 9; // Critical
    } else if (excess_ratio >= 1.5) {
        alert.severity = 7; // High
    } else if (excess_ratio >= 1.2) {
        alert.severity = 5; // Medium
    } else {
        alert.severity = 3; // Low
    }

    return alert;
}

std::string PerformancePlugin::generate_performance_report(const std::vector<PerformanceAlert>& alerts) {
    if (alerts.empty()) {
        return "No performance issues detected.";
    }

    std::ostringstream report;
    report << "Performance Analysis Report\n";
    report << "===========================\n";
    report << "Total alerts: " << alerts.size() << "\n\n";

    // Group alerts by type
    std::unordered_map<std::string, std::vector<const PerformanceAlert*>> alert_groups;
    for (const auto& alert : alerts) {
        alert_groups[alert.alert_type].push_back(&alert);
    }

    for (const auto& [alert_type, alert_list] : alert_groups) {
        report << "Alert Type: " << alert_type << " (" << alert_list.size() << " alerts)\n";
        for (const auto* alert : alert_list) {
            report << "  - " << format_performance_alert(*alert) << "\n";
        }
        report << "\n";
    }

    return report.str();
}

std::string PerformancePlugin::format_performance_alert(const PerformanceAlert& alert) {
    std::ostringstream formatted;
    auto time_t = std::chrono::system_clock::to_time_t(alert.triggered_at);
    formatted << std::put_time(std::localtime(&time_t), "%H:%M:%S");
    formatted << " [" << alert.device_id;
    if (!alert.interface.empty()) {
        formatted << ":" << alert.interface;
    }
    formatted << "] " << alert.description;
    formatted << " (threshold: " << alert.threshold_value;
    formatted << ", actual: " << alert.actual_value << ")";

    return formatted.str();
}

double PerformancePlugin::calculate_interface_utilization(uint64_t bytes_per_second, uint64_t interface_speed) {
    if (interface_speed == 0) return 0.0;
    return (static_cast<double>(bytes_per_second * 8) / interface_speed) * 100.0;
}

void PerformancePlugin::cleanup_old_metrics() {
    auto cutoff_time = std::chrono::system_clock::now() - baseline_window_;

    // Clean up metric history
    metric_history_.erase(
        std::remove_if(metric_history_.begin(), metric_history_.end(),
            [cutoff_time](const PerformanceMetric& metric) {
                return metric.timestamp < cutoff_time;
            }),
        metric_history_.end()
    );

    // Clean up bandwidth history
    for (auto& [key, samples] : bandwidth_history_) {
        samples.erase(
            std::remove_if(samples.begin(), samples.end(),
                [cutoff_time](const BandwidthSample& sample) {
                    return sample.timestamp < cutoff_time;
                }),
            samples.end()
        );
    }
}

void PerformancePlugin::cleanup_old_alerts() {
    auto cutoff_time = std::chrono::system_clock::now() - std::chrono::hours(24);

    active_alerts_.erase(
        std::remove_if(active_alerts_.begin(), active_alerts_.end(),
            [cutoff_time](const PerformanceAlert& alert) {
                return alert.triggered_at < cutoff_time;
            }),
        active_alerts_.end()
    );
}

PluginResult PerformancePlugin::analyze_device(const NetworkDevice& device) {
    auto metrics = get_performance_metrics(device);

    std::map<std::string, std::string> result_data;
    for (const auto& [key, value] : metrics) {
        result_data[key] = std::to_string(value);
    }

    return {
        true,
        "Performance analysis for " + device.name + " completed",
        result_data,
        {}, {}, {}, 0
    };
}

PluginResult PerformancePlugin::generate_performance_baseline(const NetworkDevice& device) {
    // Generate baseline from recent metrics
    std::vector<PerformanceMetric> device_metrics;
    auto cutoff_time = std::chrono::system_clock::now() - baseline_window_;

    for (const auto& metric : metric_history_) {
        if (metric.device_id == device.id && metric.timestamp >= cutoff_time) {
            device_metrics.push_back(metric);
        }
    }

    if (device_metrics.empty()) {
        return {false, "Insufficient data to generate baseline for " + device.name, {}, {}, {"No historical data"}, {}, 0};
    }

    PerformanceBaseline baseline;
    baseline.device_id = device.id;
    baseline.avg_cpu_utilization = calculate_average_metric(device_metrics, "cpu_utilization");
    baseline.avg_memory_utilization = calculate_average_metric(device_metrics, "memory_utilization");
    baseline.avg_interface_utilization = calculate_average_metric(device_metrics, "interface_utilization");
    baseline.avg_throughput_bps = static_cast<uint64_t>(calculate_average_metric(device_metrics, "throughput"));
    baseline.created_at = std::chrono::system_clock::now();
    baseline.baseline_window = std::chrono::duration_cast<std::chrono::hours>(baseline_window_);

    device_baselines_[device.id] = baseline;

    std::map<std::string, std::string> result_data;
    result_data["avg_cpu_utilization"] = std::to_string(baseline.avg_cpu_utilization);
    result_data["avg_memory_utilization"] = std::to_string(baseline.avg_memory_utilization);
    result_data["avg_interface_utilization"] = std::to_string(baseline.avg_interface_utilization);

    return {
        true,
        "Performance baseline generated for " + device.name,
        result_data,
        {}, {}, {}, 0
    };
}

std::map<std::string, double> PerformancePlugin::get_performance_metrics(const NetworkDevice& device) {
    std::map<std::string, double> metrics;

    // Get recent metrics for the device
    auto cutoff_time = std::chrono::system_clock::now() - analysis_window_;

    std::vector<double> cpu_values, memory_values, interface_values;
    for (const auto& metric : metric_history_) {
        if (metric.device_id == device.id && metric.timestamp >= cutoff_time) {
            if (metric.metric_name == "cpu_utilization") {
                cpu_values.push_back(metric.value);
            } else if (metric.metric_name == "memory_utilization") {
                memory_values.push_back(metric.value);
            } else if (metric.metric_name == "interface_utilization") {
                interface_values.push_back(metric.value);
            }
        }
    }

    // Calculate averages
    if (!cpu_values.empty()) {
        metrics["cpu_utilization"] = std::accumulate(cpu_values.begin(), cpu_values.end(), 0.0) / cpu_values.size();
    }
    if (!memory_values.empty()) {
        metrics["memory_utilization"] = std::accumulate(memory_values.begin(), memory_values.end(), 0.0) / memory_values.size();
    }
    if (!interface_values.empty()) {
        metrics["interface_utilization"] = std::accumulate(interface_values.begin(), interface_values.end(), 0.0) / interface_values.size();
    }

    return metrics;
}

double PerformancePlugin::calculate_average_metric(const std::vector<PerformanceMetric>& metrics,
                                                  const std::string& metric_name) {
    std::vector<double> values;
    for (const auto& metric : metrics) {
        if (metric.metric_name == metric_name) {
            values.push_back(metric.value);
        }
    }

    if (values.empty()) return 0.0;
    return std::accumulate(values.begin(), values.end(), 0.0) / values.size();
}

PluginResult PerformancePlugin::execute_command(const std::string& command,
                                               const std::map<std::string, std::string>& parameters) {
    if (command == "performance_report") {
        std::string report = generate_performance_report(active_alerts_);
        return {true, report, {{"report_type", "performance_analysis"}}, {}, {}, {}, 0};
    }

    if (command == "reset_alerts") {
        active_alerts_.clear();
        return {true, "Performance alerts reset", {}, {}, {}, {}, 0};
    }

    if (command == "bandwidth_report") {
        auto device_it = parameters.find("device_id");
        std::string device_id = (device_it != parameters.end()) ? device_it->second : "";
        std::string report = generate_bandwidth_report(device_id);
        return {true, report, {{"report_type", "bandwidth_analysis"}}, {}, {}, {}, 0};
    }

    return {false, "Unknown command: " + command, {}, {}, {"Unknown command"}, {}, 0};
}

PluginResult PerformancePlugin::process_real_time_entry(const LogEntry& entry) {
    std::vector<LogEntry> single_entry = {entry};
    return process_log_entries(single_entry);
}

std::vector<std::string> PerformancePlugin::get_supported_commands() const {
    return {"performance_report", "reset_alerts", "bandwidth_report"};
}

std::map<std::string, std::string> PerformancePlugin::get_configuration_schema() const {
    return {
        {"cpu_threshold", "CPU utilization threshold percentage (default: 80)"},
        {"memory_threshold", "Memory utilization threshold percentage (default: 85)"},
        {"interface_utilization_threshold", "Interface utilization threshold percentage (default: 90)"},
        {"latency_threshold", "Latency threshold in milliseconds (default: 100)"},
        {"analysis_window_minutes", "Analysis window in minutes (default: 30)"}
    };
}

std::string PerformancePlugin::get_status() const {
    if (!is_initialized_) return "not_initialized";
    if (!is_running_) return "stopped";
    return "running";
}

std::string PerformancePlugin::generate_bandwidth_report(const std::string& device_id) {
    std::ostringstream report;
    report << "Bandwidth Analysis Report";
    if (!device_id.empty()) {
        report << " - Device: " << device_id;
    }
    report << "\n" << std::string(40, '=') << "\n\n";

    for (const auto& [key, samples] : bandwidth_history_) {
        if (!device_id.empty() && key.find(device_id) != 0) {
            continue;
        }

        if (samples.empty()) continue;

        size_t separator_pos = key.find(':');
        std::string dev_id = key.substr(0, separator_pos);
        std::string interface = (separator_pos != std::string::npos) ?
            key.substr(separator_pos + 1) : "";

        report << "Interface: " << dev_id << ":" << interface << "\n";

        // Calculate statistics
        double total_utilization = 0.0;
        uint64_t max_throughput = 0;
        for (const auto& sample : samples) {
            total_utilization += sample.utilization_percent;
            max_throughput = std::max(max_throughput, sample.bytes_per_second);
        }

        double avg_utilization = total_utilization / samples.size();

        report << "  Average Utilization: " << std::fixed << std::setprecision(2)
               << avg_utilization << "%\n";
        report << "  Peak Throughput: " << max_throughput << " bytes/sec\n";
        report << "  Samples: " << samples.size() << "\n\n";
    }

    return report.str();
}

} // namespace netlogai::plugins::examples

// Plugin export macros
NETLOGAI_PLUGIN_CREATE(netlogai::plugins::examples::PerformancePlugin)
NETLOGAI_PLUGIN_DESTROY()