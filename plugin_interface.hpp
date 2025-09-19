#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace netlogai::plugins {

// Plugin API version for compatibility checking
#define NETLOGAI_PLUGIN_API_VERSION "1.0.0"

// Forward declarations
struct LogEntry;
struct NetworkDevice;
struct AnalysisResult;

// Plugin types
enum class PluginType {
    SECURITY,       // Security analysis and threat detection
    PERFORMANCE,    // Network performance monitoring
    TOPOLOGY,       // Network discovery and mapping
    PARSER,         // Custom log parsers
    ANALYTICS,      // Advanced analysis algorithms
    VISUALIZATION,  // Custom data visualization
    EXPORT,         // Data export and integration
    CUSTOM          // Generic custom functionality
};

// Plugin capabilities flags
enum class PluginCapability : uint32_t {
    NONE = 0,
    LOG_ANALYSIS = 1 << 0,         // Can analyze log entries
    REAL_TIME_MONITORING = 1 << 1,  // Supports real-time processing
    DEVICE_INTERACTION = 1 << 2,    // Can interact with network devices
    DATA_EXPORT = 1 << 3,          // Can export data
    VISUALIZATION = 1 << 4,         // Provides visualization
    ALERTING = 1 << 5,             // Can generate alerts
    CONFIGURATION = 1 << 6,         // Has configuration interface
    MULTI_THREADING = 1 << 7       // Thread-safe operations
};

inline PluginCapability operator|(PluginCapability a, PluginCapability b) {
    return static_cast<PluginCapability>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline bool operator&(PluginCapability a, PluginCapability b) {
    return (static_cast<uint32_t>(a) & static_cast<uint32_t>(b)) != 0;
}

// Plugin execution context
struct PluginContext {
    std::string plugin_id;
    std::string working_directory;
    std::map<std::string, std::string> configuration;
    std::map<std::string, std::string> environment_vars;
    uint32_t max_memory_mb;
    uint32_t max_execution_time_ms;
    bool sandbox_enabled;
};

// Plugin execution result
struct PluginResult {
    bool success;
    std::string message;
    std::map<std::string, std::string> data;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    std::chrono::milliseconds execution_time;
    uint32_t memory_used_mb;
};

// Log entry structure for plugin interface
struct LogEntry {
    std::string id;
    std::chrono::system_clock::time_point timestamp;
    std::string device_name;
    std::string device_type;
    std::string interface;
    std::string severity;
    std::string facility;
    std::string message;
    std::string raw_line;
    std::map<std::string, std::string> metadata;
};

// Network device information
struct NetworkDevice {
    std::string id;
    std::string name;
    std::string hostname;
    std::string device_type;
    std::string management_ip;
    std::map<std::string, std::string> credentials;
    std::vector<std::string> interfaces;
    bool is_online;
    std::chrono::system_clock::time_point last_seen;
};

// Analysis result structure
struct AnalysisResult {
    std::string analysis_id;
    std::string plugin_id;
    std::chrono::system_clock::time_point timestamp;
    std::string result_type;
    std::string summary;
    std::string detailed_report;
    uint32_t severity_score;
    std::vector<std::string> recommendations;
    std::map<std::string, std::string> metadata;
};

// Main plugin interface - all plugins must implement this
class INetLogAIPlugin {
public:
    virtual ~INetLogAIPlugin() = default;

    // Plugin metadata
    virtual std::string get_name() const = 0;
    virtual std::string get_version() const = 0;
    virtual std::string get_description() const = 0;
    virtual std::string get_author() const = 0;
    virtual std::string get_api_version() const = 0;
    virtual PluginType get_type() const = 0;
    virtual PluginCapability get_capabilities() const = 0;

    // Plugin lifecycle
    virtual bool initialize(const PluginContext& context) = 0;
    virtual bool configure(const std::map<std::string, std::string>& config) = 0;
    virtual bool start() = 0;
    virtual bool stop() = 0;
    virtual void cleanup() = 0;

    // Core functionality
    virtual PluginResult process_log_entries(const std::vector<LogEntry>& entries) = 0;
    virtual PluginResult analyze_device(const NetworkDevice& device) = 0;
    virtual PluginResult execute_command(const std::string& command,
                                       const std::map<std::string, std::string>& parameters) = 0;

    // Optional interfaces (default implementations)
    virtual bool supports_real_time() const { return get_capabilities() & PluginCapability::REAL_TIME_MONITORING; }
    virtual PluginResult process_real_time_entry(const LogEntry& /* entry */) { return {false, "Real-time processing not supported", {}, {}, {}, {}, 0}; }
    virtual std::vector<std::string> get_supported_commands() const { return {}; }
    virtual std::map<std::string, std::string> get_configuration_schema() const { return {}; }
    virtual std::string get_status() const { return "unknown"; }
};

// Specialized plugin interfaces
class ISecurityPlugin : public INetLogAIPlugin {
public:
    PluginType get_type() const override { return PluginType::SECURITY; }

    // Security-specific methods
    virtual PluginResult detect_threats(const std::vector<LogEntry>& entries) = 0;
    virtual PluginResult analyze_authentication_failures(const std::vector<LogEntry>& entries) = 0;
    virtual PluginResult scan_for_vulnerabilities(const NetworkDevice& device) = 0;
    virtual std::vector<std::string> get_threat_signatures() const = 0;
};

class IPerformancePlugin : public INetLogAIPlugin {
public:
    PluginType get_type() const override { return PluginType::PERFORMANCE; }

    // Performance-specific methods
    virtual PluginResult analyze_bandwidth_usage(const std::vector<LogEntry>& entries) = 0;
    virtual PluginResult detect_performance_issues(const std::vector<LogEntry>& entries) = 0;
    virtual PluginResult generate_performance_baseline(const NetworkDevice& device) = 0;
    virtual std::map<std::string, double> get_performance_metrics(const NetworkDevice& device) = 0;
};

class ITopologyPlugin : public INetLogAIPlugin {
public:
    PluginType get_type() const override { return PluginType::TOPOLOGY; }

    // Topology-specific methods
    virtual PluginResult discover_network_devices() = 0;
    virtual PluginResult map_device_connections(const std::vector<NetworkDevice>& devices) = 0;
    virtual PluginResult generate_topology_diagram() = 0;
    virtual std::vector<NetworkDevice> get_discovered_devices() const = 0;
};

// Plugin factory function signature
typedef INetLogAIPlugin* (*CreatePluginFunc)();
typedef void (*DestroyPluginFunc)(INetLogAIPlugin*);

// Plugin manifest structure (for plugin.json files)
struct PluginManifest {
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::string api_version;
    std::string plugin_type;
    std::vector<std::string> capabilities;
    std::string entry_point;  // DLL/SO filename
    std::string config_schema; // JSON schema for configuration
    std::vector<std::string> dependencies;
    std::map<std::string, std::string> metadata;
};

} // namespace netlogai::plugins

// C-style plugin export macros for cross-platform compatibility
#ifdef _WIN32
    #define NETLOGAI_PLUGIN_EXPORT __declspec(dllexport)
#else
    #define NETLOGAI_PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

// Macros to simplify plugin creation
#define NETLOGAI_PLUGIN_CREATE(PluginClass) \
    extern "C" NETLOGAI_PLUGIN_EXPORT netlogai::plugins::INetLogAIPlugin* create_plugin() { \
        return new PluginClass(); \
    }

#define NETLOGAI_PLUGIN_DESTROY() \
    extern "C" NETLOGAI_PLUGIN_EXPORT void destroy_plugin(netlogai::plugins::INetLogAIPlugin* plugin) { \
        delete plugin; \
    }