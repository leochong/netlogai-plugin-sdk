# NetLogAI Plugin SDK

**Extensible Plugin Development Framework for Network Log Analysis**

Create powerful plugins that extend NetLogAI's capabilities with custom analysis, integrations, and specialized network device support.

[![Build Status](https://github.com/NetLogAI/netlogai-plugin-sdk/workflows/CI/badge.svg)](https://github.com/NetLogAI/netlogai-plugin-sdk/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)

## 🎯 Overview

The NetLogAI Plugin SDK enables developers to create sophisticated plugins that integrate seamlessly with the NetLogAI ecosystem. Whether you're building security analysis tools, performance monitors, or custom device support, the SDK provides everything you need.

## ✨ Key Features

### 🔌 Plugin Architecture
- **Type-Safe Interfaces**: Modern C++20 concepts and interfaces
- **Hot Reload**: Load and unload plugins without restarting
- **Dependency Management**: Automatic plugin dependency resolution
- **Sandboxed Execution**: Safe execution environment for third-party plugins

### 🛠️ Development Tools
- **Plugin Templates**: Quick-start templates for common plugin types
- **Testing Framework**: Comprehensive unit and integration testing
- **Debugging Support**: Full debugging capabilities with NetLogAI Core
- **Performance Profiling**: Built-in performance monitoring and optimization

### 🔒 Security & Safety
- **API Validation**: Input/output validation for all plugin interactions
- **Resource Limits**: Memory and CPU usage constraints
- **Permission System**: Fine-grained access control for system resources
- **Code Signing**: Digital signature verification for production plugins

## 🚀 Quick Start

### Installation

```bash
# Clone the SDK
git clone https://github.com/NetLogAI/netlogai-plugin-sdk.git
cd netlogai-plugin-sdk

# Build the SDK
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel

# Install development headers
cmake --install . --prefix /usr/local
```

### Create Your First Plugin

```bash
# Generate a new plugin from template
./tools/create-plugin.sh --name MySecurityAnalyzer --type security

# This creates:
# plugins/my-security-analyzer/
# ├── CMakeLists.txt
# ├── plugin.json
# ├── src/
# │   ├── plugin.cpp
# │   └── plugin.hpp
# └── tests/
```

### Basic Plugin Structure

```cpp
#include <netlogai/plugin_sdk.hpp>

class MySecurityAnalyzer : public netlogai::SecurityPlugin {
public:
    // Plugin metadata
    std::string getName() const override {
        return "My Security Analyzer";
    }
    
    std::string getVersion() const override {
        return "1.0.0";
    }
    
    // Initialize plugin
    bool initialize(const netlogai::PluginConfig& config) override {
        // Setup your plugin
        return true;
    }
    
    // Process log entries
    netlogai::AnalysisResult analyze(const netlogai::LogEntry& entry) override {
        netlogai::AnalysisResult result;
        
        if (entry.message.find("failed login") != std::string::npos) {
            result.severity = netlogai::Severity::High;
            result.threat_type = "Authentication Failure";
            result.description = "Potential brute force attack detected";
            result.recommendations.push_back("Monitor source IP for repeated failures");
        }
        
        return result;
    }
};

// Register plugin with NetLogAI
NETLOGAI_REGISTER_PLUGIN(MySecurityAnalyzer)
```

## 🔧 Plugin Types

### Security Analysis Plugins
Monitor logs for security threats, anomalies, and compliance violations.

```cpp
class SecurityPlugin : public netlogai::IPlugin {
    virtual AnalysisResult analyze(const LogEntry& entry) = 0;
    virtual std::vector<ThreatIndicator> getThreatIndicators() = 0;
    virtual ComplianceReport generateComplianceReport() = 0;
};
```

### Performance Monitoring Plugins
Track network performance metrics and identify bottlenecks.

```cpp
class PerformancePlugin : public netlogai::IPlugin {
    virtual MetricsResult collectMetrics(const LogEntry& entry) = 0;
    virtual PerformanceReport generateReport(TimeRange range) = 0;
    virtual std::vector<Anomaly> detectAnomalies() = 0;
};
```

### Network Topology Plugins
Discover and visualize network topology from log data.

```cpp
class TopologyPlugin : public netlogai::IPlugin {
    virtual TopologyGraph buildTopology(const LogStream& logs) = 0;
    virtual std::vector<NetworkDevice> discoverDevices() = 0;
    virtual ConnectionMap mapConnections() = 0;
};
```

### Integration Plugins
Connect NetLogAI with external systems and APIs.

```cpp
class IntegrationPlugin : public netlogai::IPlugin {
    virtual bool sendAlert(const Alert& alert) = 0;
    virtual ExternalData fetchData(const Query& query) = 0;
    virtual bool synchronizeData() = 0;
};
```

## 📚 Advanced Features

### Plugin Configuration
```json
{
    "name": "my-security-analyzer",
    "version": "1.0.0",
    "type": "security",
    "author": "Your Name",
    "description": "Advanced security analysis for network logs",
    "dependencies": {
        "libnetlog": ">=1.0.0",
        "openssl": ">=1.1.0"
    },
    "permissions": [
        "network.read",
        "file.write:/var/log/alerts"
    ],
    "configuration": {
        "alert_threshold": {
            "type": "integer",
            "default": 5,
            "description": "Number of failed logins before alert"
        },
        "notification_email": {
            "type": "string",
            "required": true,
            "description": "Email for security alerts"
        }
    }
}
```

### Event Handling
```cpp
class EventAwarePlugin : public netlogai::IPlugin {
public:
    void onLogEntry(const LogEntry& entry) override {
        // Process each log entry
    }
    
    void onDeviceConnect(const DeviceInfo& device) override {
        // Handle new device connections
    }
    
    void onAlert(const Alert& alert) override {
        // React to system alerts
    }
    
    void onConfigChange(const ConfigUpdate& update) override {
        // Handle configuration updates
    }
};
```

### Data Persistence
```cpp
class DataPersistentPlugin : public netlogai::IPlugin {
private:
    netlogai::PluginDatabase db_;
    
public:
    bool initialize(const PluginConfig& config) override {
        db_ = getPluginDatabase("my_plugin_data");
        return db_.isValid();
    }
    
    void storeAnalysisResult(const AnalysisResult& result) {
        db_.store("analysis_results", result.toJson());
    }
    
    std::vector<AnalysisResult> getHistoricalResults(TimeRange range) {
        return db_.query("analysis_results", range);
    }
};
```

## 🧪 Testing Your Plugin

### Unit Testing
```cpp
#include <netlogai/plugin_test_framework.hpp>

TEST_F(SecurityPluginTest, DetectBruteForceAttack) {
    auto plugin = std::make_unique<MySecurityAnalyzer>();
    auto config = createTestConfig();
    ASSERT_TRUE(plugin->initialize(config));
    
    // Create test log entry
    LogEntry entry;
    entry.message = "Authentication failed for user admin from 192.168.1.100";
    entry.severity = Severity::Warning;
    
    // Test analysis
    auto result = plugin->analyze(entry);
    EXPECT_EQ(result.severity, Severity::High);
    EXPECT_EQ(result.threat_type, "Authentication Failure");
}
```

### Integration Testing
```cpp
TEST_F(PluginIntegrationTest, SecurityPluginWithRealLogs) {
    auto plugin_manager = createTestPluginManager();
    plugin_manager.loadPlugin("my-security-analyzer");
    
    // Load sample log files
    auto logs = loadSampleLogs("security_test_logs.txt");
    
    // Process logs through plugin
    std::vector<AnalysisResult> results;
    for (const auto& log : logs) {
        auto result = plugin_manager.processLogEntry(log);
        if (result.hasResults()) {
            results.push_back(result);
        }
    }
    
    // Verify results
    EXPECT_GT(results.size(), 0);
    EXPECT_TRUE(containsThreatType(results, "Authentication Failure"));
}
```

## 📖 Examples

### Security Analysis Plugin
Detect and alert on security threats:
- [Brute Force Detector](examples/security/brute-force-detector/)
- [Malware Communication Analyzer](examples/security/malware-analyzer/)
- [Compliance Monitor](examples/security/compliance-monitor/)

### Performance Monitoring Plugin
Monitor network performance metrics:
- [Bandwidth Monitor](examples/performance/bandwidth-monitor/)
- [Latency Tracker](examples/performance/latency-tracker/)
- [Device Health Monitor](examples/performance/device-health/)

### Integration Plugin
Connect with external systems:
- [SIEM Integration](examples/integration/siem-connector/)
- [Slack Notifications](examples/integration/slack-notifier/)
- [Database Exporter](examples/integration/db-exporter/)

## 🔧 Development Tools

### Plugin Generator
```bash
# Create different types of plugins
./tools/create-plugin.sh --type security --name ThreatDetector
./tools/create-plugin.sh --type performance --name BandwidthMonitor  
./tools/create-plugin.sh --type topology --name NetworkMapper
./tools/create-plugin.sh --type integration --name SlackNotifier
```

### Plugin Validator
```bash
# Validate plugin structure and metadata
./tools/validate-plugin.sh plugins/my-plugin/

# Check plugin security and safety
./tools/security-audit.sh plugins/my-plugin/
```

### Development Server
```bash
# Start development server with hot reload
./tools/dev-server.sh --plugin-dir plugins/my-plugin/ --log-file sample_logs.txt
```

## 📦 Plugin Distribution

### Building Release Package
```bash
# Build optimized plugin
cmake --build build --config Release --target my-security-analyzer

# Create distribution package
./tools/package-plugin.sh --plugin my-security-analyzer --version 1.0.0
```

### Plugin Marketplace
- Submit to [NetLogAI Plugin Marketplace](https://plugins.netlogai.com)
- Automated testing and security validation
- Revenue sharing for commercial plugins
- Community ratings and reviews

## 🤝 Contributing

We welcome plugin developers and SDK contributors! 

### Plugin Contribution
- Submit plugins to our community repository
- Share templates and best practices
- Improve documentation and examples

### SDK Development
- Enhance plugin interfaces and capabilities
- Add new plugin types and frameworks
- Improve security and performance

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Resources

- [Plugin Development Guide](docs/plugin-development.md)
- [API Reference](docs/api/README.md)
- [Best Practices](docs/best-practices.md)
- [Security Guidelines](docs/security.md)
- [Community Forum](https://community.netlogai.com)

---

**Build powerful network analysis tools with NetLogAI Plugin SDK**

For support and discussions, join our [Discord community](https://discord.gg/netlogai) or visit our [community forum](https://community.netlogai.com).