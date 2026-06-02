# Copper Sun Brass v2.0 - Architecture Documentation

## Executive Summary

Copper Sun Brass v2.0 represents a **CLI-induced architecture** approach to AI development intelligence, in contrast to the original BrassCoders system's **monitoring-based architecture**. This design choice fundamentally changes how developers interact with the system and when intelligence is generated.

## Architectural Philosophy Comparison

### Original BrassCoders: Monitoring-Based Architecture

**Core Principle**: "Set it and forget it" continuous intelligence

```bash
brass init    # Start once, automatic from here
# Background agents run continuously
# Intelligence files stay current automatically  
# Claude Code always has fresh context
```

**Characteristics:**
- **4 Background Agents**: Scout, Watch, Strategist, Planner
- **Automatic Operation**: Zero ongoing user intervention
- **Continuous Updates**: Intelligence files refreshed automatically
- **Daemon-like Process**: Runs independently across sessions
- **Always-Current Context**: AI assistants get real-time project state

### New BrassCoders v2.0: CLI-Induced Architecture

**Core Principle**: "Run when needed" on-demand intelligence

```bash
brass2 scan   # Analyze now
brass2 watch  # Monitor when requested
brass2 status # Check current state
```

**Characteristics:**
- **6 CLI Components**: CodeScanner, PrivacyScanner, IntelligenceRanker, OutputGenerator, FileWatcher, CLI
- **User-Controlled**: Analysis happens when commanded
- **On-Demand Updates**: Intelligence generated per request
- **Command-Line Tool**: Traditional CLI application model
- **Snapshot Context**: AI assistants get point-in-time project analysis

## Detailed Architecture Comparison

| Aspect | Original BrassCoders | BrassCoders v2.0 |
|--------|---------------|-------------|
| **Execution Model** | Background daemon | CLI commands |
| **Startup Command** | `brass init` | `brass2 scan` |
| **User Interaction** | Once → automatic | Per-analysis → manual |
| **Intelligence Freshness** | Real-time | On-demand |
| **Process Lifecycle** | Long-running | Per-invocation |
| **Resource Usage** | Continuous low | Burst high |
| **AI Context Currency** | Always fresh | Fresh when run |
| **Development Workflow** | Passive monitoring | Active analysis |

## Component Architecture - BrassCoders v2.0

### Core Components

#### 1. CodeScanner
- **Purpose**: Python AST static code analysis
- **Technology**: Python `ast` module
- **Detects**: Security issues, code quality problems, TODOs, complexity
- **Execution**: On-demand via CLI

#### 2. PrivacyScanner  
- **Purpose**: PII and privacy compliance analysis
- **Technology**: DualPurposeContentSafety integration
- **Detects**: Personal data, credentials, compliance violations
- **Execution**: On-demand via CLI

#### 3. IntelligenceRanker
- **Purpose**: Unified finding prioritization
- **Technology**: Weighted scoring algorithm
- **Function**: Ranks all findings by importance for AI consumption
- **Execution**: Post-analysis processing

#### 4. OutputGenerator
- **Purpose**: AI-optimized intelligence file generation
- **Technology**: Structured markdown + JSON export
- **Outputs**: 6 intelligence files optimized for Claude Code
- **Execution**: Final step in analysis pipeline

#### 5. FileWatcher
- **Purpose**: Real-time change monitoring (optional)
- **Technology**: Polling-based file system monitoring
- **Function**: Triggers re-analysis on file changes
- **Execution**: Only when `brass2 watch` is active

#### 6. CLI Interface
- **Purpose**: User-friendly command interface
- **Technology**: Python argparse
- **Commands**: scan, watch, status, version, report
- **Execution**: Entry point for all functionality

### Data Flow Architecture

```
User Command (brass2 scan)
↓
CLI Interface
↓
Component Initialization
├── CodeScanner.scan()
├── PrivacyScanner.scan() 
└── → Raw Findings
↓
IntelligenceRanker.rank_findings()
├── Weighted scoring
├── Priority calculation
└── → Ranked Findings
↓
OutputGenerator.generate_intelligence()
├── AI_INSTRUCTIONS.md
├── DETAILED_ANALYSIS.md
├── SECURITY_REPORT.md
├── analysis_data.json
├── STATISTICS.md
└── FILE_INTELLIGENCE.md
```

## Use Case Comparison

### Original BrassCoders Use Cases
- **Continuous AI Context**: AI assistants always have current project intelligence
- **Background Monitoring**: Detect issues as they're introduced
- **Zero-Touch Intelligence**: Developers focus on coding, not analysis
- **Real-Time Insights**: Intelligence reflects current project state

### BrassCoders v2.0 Use Cases
- **Pre-Commit Analysis**: Run before commits to catch issues
- **Periodic Project Health**: Schedule analysis runs
- **Investigation Mode**: Deep-dive analysis when needed
- **Development Tool Integration**: Part of development workflow

## Integration Patterns

### Original BrassCoders Integration
```bash
# One-time setup
brass init

# Claude Code automatically gets:
# - Current security findings
# - Recent code changes
# - Active TODOs
# - Project health metrics
```

### BrassCoders v2.0 Integration
```bash
# Per-session analysis
brass2 scan

# Claude Code gets:
# - Point-in-time analysis
# - Comprehensive findings
# - Rich intelligence files
# - Manual update cycle
```

## Trade-offs Analysis

### CLI-Induced Advantages
✅ **Predictable Resource Usage**: Only runs when needed
✅ **User Control**: Developers choose when to analyze
✅ **Traditional Workflow**: Fits existing development patterns
✅ **Debugging Friendly**: Easier to troubleshoot individual runs
✅ **Simpler Architecture**: No background process management

### CLI-Induced Disadvantages
❌ **Manual Intervention**: Requires developer action
❌ **Stale Intelligence**: AI context can become outdated
❌ **Workflow Friction**: Additional step in development process
❌ **Inconsistent Updates**: Intelligence freshness varies

### Monitoring-Based Advantages
✅ **Always Current**: Intelligence reflects real-time state
✅ **Zero Friction**: No developer action required
✅ **Proactive Detection**: Issues caught immediately
✅ **Consistent Updates**: Regular intelligence refresh
✅ **Seamless AI Context**: Always-fresh context for assistants

### Monitoring-Based Disadvantages
❌ **Resource Overhead**: Continuous background processing
❌ **Complexity**: Background agent management
❌ **Less Predictable**: Analysis timing controlled by system
❌ **Debugging Challenges**: Background process troubleshooting

## Future Evolution Path

### Hybrid Architecture Possibility
Future versions could combine both approaches:

```bash
# Monitoring mode (original)
brass init --background

# CLI mode (v2.0)  
brass2 scan

# Hybrid mode (future)
brass3 auto --with-cli
```

This would provide:
- Background monitoring for continuous intelligence
- CLI commands for on-demand deep analysis
- User choice of interaction model
- Best of both architectural approaches

## Conclusion

BrassCoders v2.0's CLI-induced architecture represents a deliberate design choice favoring user control and traditional development workflows over continuous automation. This approach trades the "always current" intelligence of the original system for predictable, user-controlled analysis that fits better into established development practices.

Both architectures serve valid use cases, and the choice between them reflects different philosophies about how AI development intelligence should be integrated into the software development lifecycle.