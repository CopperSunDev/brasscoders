# 🎺 Copper Sun Brass v2.0 - CLI User Guide

> **Complete guide to using the BrassCoders command-line interface for AI development intelligence**

## 📖 Overview

The BrassCoders CLI provides a powerful, user-friendly interface for analyzing your code and generating rich intelligence reports for AI coding assistants. This guide covers everything from basic usage to advanced workflows.

## 🚀 Quick Start

### Basic Analysis
```bash
# Complete analysis (recommended)
brass scan

# Quick code review (skips privacy/content checks)
brass scan --fast

# Developer focus (source code only, excludes tests/build files)
brass scan --dev
```

### Targeted Analysis
```bash
# Code quality, bugs, and security only
brass scan --code

# Privacy and PII detection only
brass scan --privacy

# Content moderation and policy checks only
brass scan --content
```

## 📋 Command Reference

### Global Options

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable detailed logging output |
| `--project-path PATH` | Specify project directory (default: current directory) |
| `--log-file PATH` | 📝 Custom log file location (default: `.brass/brass.log`) |
| `--no-log-file` | 🚫 Disable automatic log file creation |

### Commands

#### `brass scan` - Code Analysis

Analyzes your codebase for security issues, code quality problems, privacy concerns, and policy violations.

**Usage:**
```bash
brass scan [PATH] [OPTIONS]
```

**Arguments:**
- `PATH` - Project directory to analyze (default: current directory)

**User-Friendly Options:**
- `--fast` - ⚡ Quick scan: code analysis only (skips privacy/content for speed)
- `--dev` - 👨‍💻 Developer mode: focus on source code (excludes tests/build files)
- `--code` - 🐛 Code analysis only: bugs, security, code quality
- `--privacy` - 🔒 Privacy analysis only: PII detection, data protection
- `--content` - 🚫 Content moderation only: policy violations, inappropriate content

**Configuration Options:**
- `--output-dir DIR` - Custom output directory (default: `.brass`)

**Examples:**
```bash
# Analyze current project completely
brass scan

# Quick code review for development
brass scan --fast

# Focus on production source code only
brass scan --dev

# Analyze specific project with custom output
brass scan /path/to/project --output-dir reports

# Security and code quality only
brass scan --code

# Check for sensitive data exposure
brass scan --privacy
```

#### `brass watch` - Continuous Monitoring

Monitor your codebase for changes and automatically re-analyze when files are modified.

**Usage:**
```bash
brass watch [OPTIONS]
```

**Options:**
- `--poll-interval SECONDS` - How often to check for changes (default: 2.0)
- `--debounce-delay SECONDS` - Wait time after changes stop before analyzing (default: 5.0)

**Examples:**
```bash
# Start monitoring with default settings
brass watch

# Custom polling settings for large projects
brass watch --poll-interval 5.0 --debounce-delay 10.0
```

#### `brass status` - View Analysis Results

Display summary of your latest analysis results and statistics.

**Usage:**
```bash
brass status
```

**Output includes:**
- Analysis timestamp and file status
- Finding counts by type and severity
- File coverage statistics
- Quick summary of critical issues

#### `brass version` - System Information

Show version details and component status.

**Usage:**
```bash
brass version
```

## 📁 Output Files

BrassCoders generates several intelligence files in the output directory (default: `.brass/`):

### Primary Intelligence Files

| File | Purpose |
|------|---------|
| `ai_instructions.yaml` | 🎯 **Start here!** - Main guidance optimized for AI assistants like Claude Code |
| `detailed_analysis.yaml` | 📊 Complete technical breakdown of all issues found |
| `security_report.yaml` | 🔒 Security vulnerabilities that need immediate attention |
| `privacy_analysis.yaml` | 🛡️ Personal data (PII) exposure and compliance issues |
| `file_intelligence.yaml` | 📋 File-by-file breakdown showing problems in each file |
| `statistics.yaml` | 📈 Summary metrics and trends across your entire project |

### Utility Files

| File | Purpose |
|------|---------|
| `error_report.json` | ⚠️ Analysis errors and warnings (if any) |

## 🎯 Common Workflows

### Daily Development Workflow

1. **Initial scan** of your project:
   ```bash
   brass scan
   ```

2. **Review findings** in ai_instructions.yaml with your AI assistant

3. **Monitor changes** during development:
   ```bash
   brass watch
   ```

4. **Quick checks** before commits:
   ```bash
   brass scan --fast
   ```

### Security Review Workflow

1. **Complete security analysis**:
   ```bash
   brass scan --code
   ```

2. **Check for data exposure**:
   ```bash
   brass scan --privacy
   ```

3. **Review reports**:
   - Security findings: `.brass/security_report.yaml`
   - Privacy analysis: `.brass/privacy_analysis.yaml`

### Code Quality Workflow

1. **Developer-focused analysis**:
   ```bash
   brass scan --dev
   ```

2. **Address critical issues** shown in output

3. **Re-scan** to verify fixes:
   ```bash
   brass scan --dev
   ```

4. **Check status**:
   ```bash
   brass status
   ```

## 🔧 Configuration

### Output Directory

Control where intelligence files are generated:

```bash
# Use custom directory
brass scan --output-dir ./reports

# Organize by date
brass scan --output-dir ./analysis/$(date +%Y-%m-%d)
```

### 📝 Logging & Debugging

BrassCoders automatically creates detailed log files for debugging and audit purposes:

#### Default Behavior
```bash
# Creates .brass/brass.log automatically
brass scan
```

#### Custom Log Location
```bash
# Specify custom log file
brass scan --log-file ./logs/brass-$(date +%Y%m%d).log

# Store logs in project-specific location
brass scan --log-file ~/.brass/logs/$(basename $PWD).log
```

#### Disable Logging
```bash
# No log file creation
brass scan --no-log-file
```

#### Verbose Logging
```bash
# Detailed debug information in log file
brass -v scan
```

**What gets logged:**
- Session start/end timestamps
- Configuration and command-line options
- Scanner execution and performance metrics  
- File processing errors and warnings
- System events and component initialization

**Log file benefits:**
- **Debugging**: Share log files when reporting issues
- **Audit trail**: Track what was scanned and when
- **Performance analysis**: Identify slow scanners or large files
- **Error diagnosis**: Capture permission issues, network problems, etc.

**Note**: Console output remains clean (WARNING+ only), while log files capture detailed INFO+ messages.

### Filtering for Large Projects

For large codebases, use focused analysis:

```bash
# Developer mode excludes test files, fixtures, build artifacts
brass scan --dev

# Code-only for faster iteration
brass scan --code

# Fast mode for quick checks
brass scan --fast
```

## 🚨 Understanding Findings

### Severity Levels

- **Critical** 🚨 - Immediate security risks, exposed secrets
- **High** ⚠️ - Significant security or quality issues
- **Medium** 📊 - Code quality and maintainability concerns
- **Low** 💡 - Minor improvements and suggestions
- **Info** ℹ️ - Informational findings and best practices

### Finding Types

- **Security** 🔒 - Vulnerabilities, exposed secrets, unsafe patterns
- **Privacy** 🛡️ - PII exposure, data protection concerns
- **Code Quality** 🐛 - Complexity, maintainability, best practices
- **TODO** 📝 - Development tasks and technical debt
- **Architecture** 🏗️ - Design patterns and structural concerns

## 💡 Tips and Best Practices

### Effective Usage

1. **Start with complete analysis** - Run `brass scan` first to get the full picture
2. **Use developer mode for focus** - `brass scan --dev` filters out test noise
3. **Monitor during development** - `brass watch` catches issues early
4. **Review ai_instructions.yaml** - This is the main file optimized for AI assistants

### Performance Optimization

1. **Use --fast for iteration** - Quick feedback during development
2. **Use --dev for production focus** - Excludes test files and build artifacts
3. **Custom output directories** - Organize reports by feature or sprint

### How to Use Your Analysis Results

#### For AI Coding Assistance
- **🤖 Start with `ai_instructions.yaml`** - This file is specifically formatted for Claude Code and other AI assistants
- **📂 Drill down with `file_intelligence.yaml`** - Shows problems in each specific file
- **🔒 Address security first** - Review `security_report.yaml` for critical vulnerabilities

#### For Security Review
- **🚨 Priority: `security_report.yaml`** - Start here for security-focused reviews
- **🛡️ Privacy compliance: `privacy_analysis.yaml`** - Check for PII exposure and data protection issues
- **📊 Overall view: `statistics.yaml`** - Get project-wide security metrics

#### For Project Management
- **📈 Metrics: `statistics.yaml`** - Track code quality trends over time
- **📋 Detailed breakdown: `detailed_analysis.yaml`** - Technical deep-dive for architecture decisions
- **📂 File prioritization: `file_intelligence.yaml`** - Focus efforts on most problematic files

### Integration with AI Assistants

1. **Share ai_instructions.yaml** with Claude Code or other AI tools
2. **Reference specific findings** by file and line number
3. **Copy relevant sections** from any YAML file for focused discussions

## 🔍 Troubleshooting

### Common Issues

**No findings detected:**
- Ensure you're in the correct project directory
- Check that source files exist and are readable
- Try `brass scan --verbose` for detailed logging

**Permission errors:**
- Ensure write access to output directory
- Check file permissions on project files

**Large project performance:**
- Use `brass scan --dev` to focus on source code
- Use `brass scan --fast` for quicker iteration
- Consider custom `--output-dir` on faster storage

### Getting Help

```bash
# Command help
brass --help
brass scan --help

# System information
brass version

# Verbose logging for debugging
brass scan --verbose
```

## 🚀 Advanced Usage

### Scripting and Automation

```bash
#!/bin/bash
# Pre-commit analysis script

echo "Running BrassCoders analysis..."
if brass scan --fast --output-dir .brass-precommit; then
    echo "✅ Analysis complete - check .brass-precommit/ai_instructions.yaml"
else
    echo "❌ Analysis failed"
    exit 1
fi
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Run BrassCoders Analysis
  run: |
    brass scan --output-dir ./brass-reports
    # Upload reports as artifacts or integrate with PR comments
```

### Custom Filtering

```bash
# Focus on specific file types or directories
brass scan src/ --dev                    # Analyze src directory only
brass scan --dev --output-dir ./focused  # Custom output location
```

---

**🎺 Copper Sun Brass v2.0** - Revolutionary AI Development Intelligence

*For more information, updates, and community support, visit the project documentation.*