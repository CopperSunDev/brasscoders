#!/usr/bin/env node
/**
 * Babel Parser for JavaScript/TypeScript Analysis
 * 
 * This script uses @babel/parser and @babel/traverse to parse JS/TS files
 * and extract AST information for security and quality analysis.
 */

const fs = require('fs');
const path = require('path');
const { parse } = require('@babel/parser');
const traverse = require('@babel/traverse').default;

// Parser configuration for maximum compatibility
const BABEL_CONFIG = {
  sourceType: 'unambiguous',  // Auto-detect module vs script
  allowImportExportEverywhere: true,
  allowAwaitOutsideFunction: true,
  allowReturnOutsideFunction: true,
  allowSuperOutsideMethod: true,
  allowUndeclaredExports: true,
  strictMode: false,
  plugins: [
    // Language features
    'jsx',
    'typescript',
    'decorators-legacy',
    'classProperties',
    'classPrivateProperties',
    'classPrivateMethods',
    'functionBind',
    'exportDefaultFrom',
    'exportNamespaceFrom',
    'dynamicImport',
    'nullishCoalescingOperator',
    'optionalChaining',
    'optionalCatchBinding',
    'throwExpressions',
    'topLevelAwait',
    'importMeta',
    // Experimental features
    'asyncGenerators',
    'bigInt',
    'objectRestSpread',
    'functionSent',
    'partialApplication'
  ]
};

/**
 * Parse a single file and extract analysis data
 */
function parseFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const ast = parse(content, BABEL_CONFIG);
    
    const analysisData = {
      file: filePath,
      success: true,
      ast: ast,
      patterns: extractPatterns(ast, content),
      metrics: calculateMetrics(ast, content),
      errors: []
    };
    
    return analysisData;
    
  } catch (error) {
    return {
      file: filePath,
      success: false,
      ast: null,
      patterns: [],
      metrics: {},
      errors: [{
        type: 'parse_error',
        message: error.message,
        line: error.loc ? error.loc.line : null,
        column: error.loc ? error.loc.column : null
      }]
    };
  }
}

/**
 * Identify if a StringLiteral is being assigned to an identifier, and
 * return that identifier's name. Returns null if the literal is not
 * in an assignment context (e.g. function-call argument, array element,
 * JSX attribute value, etc.).
 *
 * Used by the hardcoded-credential detector to require an assignment
 * context — fires on `const password = "..."`, not on
 * `console.error('Password reset error:', err)`.
 */
function identifierAssignedTo(path) {
  const parent = path.parent;
  if (!parent) return null;

  // const password = "..." / let secret = "..."
  if (parent.type === 'VariableDeclarator' &&
      parent.init === path.node &&
      parent.id?.type === 'Identifier') {
    return parent.id.name;
  }

  // { password: "..." } and shorthand-equivalent { "password": "..." }
  if (parent.type === 'ObjectProperty' && parent.value === path.node) {
    if (parent.key?.type === 'Identifier') return parent.key.name;
    if (parent.key?.type === 'StringLiteral') return parent.key.value;
  }

  // obj.password = "..." or password = "..."
  if (parent.type === 'AssignmentExpression' && parent.right === path.node) {
    const left = parent.left;
    if (left.type === 'Identifier') return left.name;
    if (left.type === 'MemberExpression' && left.property?.type === 'Identifier') {
      return left.property.name;
    }
  }

  // TS: `password: "..."` in interface/type contexts isn't a runtime
  // value, but we treat object-property assignments uniformly above.

  // Default-export-style or named-export with VariableDeclarator handled
  // by the VariableDeclarator branch since AST normalizes to that.

  return null;
}

/**
 * True if the identifier name looks like a credential. Word boundaries
 * matter: "key" by itself matches, but "monkey" doesn't.
 */
function isCredentialIdentifierName(name) {
  return /(^|_|\b)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|priv(ate)?[_-]?key|auth[_-]?token|access[_-]?token|bearer[_-]?token|client[_-]?secret|jwt[_-]?secret|session[_-]?secret)(\b|_|$)/i.test(name);
}

/**
 * True if the string value plausibly looks like a credential rather
 * than a sentence or placeholder. Conservative: real credentials are
 * typically space-free, of meaningful length, and contain digits or
 * symbols.
 */
function looksLikeCredentialValue(value) {
  if (typeof value !== 'string') return false;
  // Real credentials don't typically contain whitespace.
  if (/\s/.test(value)) return false;
  // Too short to be useful as a credential.
  if (value.length < 8) return false;
  // Empty / placeholder strings.
  if (/^(your[_-]?\w+|<[a-z_]+>|TODO|FIXME|xxx|placeholder|change[_-]?me|example)$/i.test(value)) {
    return false;
  }
  // Process-template references aren't literal values.
  if (value.startsWith('${') || value.startsWith('process.env.')) return false;
  // Must contain at least one digit or non-alphanumeric character — the
  // mix that distinguishes credentials from sentences.
  if (!/[\d\W_]/.test(value)) return false;
  return true;
}

/**
 * Extract security and quality patterns from AST
 */
function extractPatterns(ast, content) {
  const patterns = [];
  const lines = content.split('\n');
  
  traverse(ast, {
    // Security patterns
    CallExpression(path) {
      const node = path.node;
      
      // Dangerous eval usage
      if (node.callee.name === 'eval') {
        patterns.push({
          type: 'security',
          pattern: 'dangerous_eval',
          severity: 'high',
          line: node.loc.start.line,
          column: node.loc.start.column,
          message: 'Use of eval() is dangerous and should be avoided',
          code: lines[node.loc.start.line - 1]
        });
      }
      
      // innerHTML with user input (potential XSS)
      if (node.callee.type === 'MemberExpression' && 
          node.callee.property && 
          node.callee.property.name === 'innerHTML') {
        patterns.push({
          type: 'security',
          pattern: 'innerHTML_usage',
          severity: 'medium',
          line: node.loc.start.line,
          column: node.loc.start.column,
          message: 'innerHTML usage detected - potential XSS vulnerability',
          code: lines[node.loc.start.line - 1]
        });
      }
      
      // document.write (XSS risk)
      if (node.callee.type === 'MemberExpression' &&
          node.callee.object && node.callee.object.name === 'document' &&
          node.callee.property && node.callee.property.name === 'write') {
        patterns.push({
          type: 'security',
          pattern: 'document_write',
          severity: 'high',
          line: node.loc.start.line,
          column: node.loc.start.column,
          message: 'document.write() is deprecated and vulnerable to XSS',
          code: lines[node.loc.start.line - 1]
        });
      }
    },
    
    // Hardcoded secrets in strings
    StringLiteral(path) {
      const value = path.node.value;
      
      // API key patterns - more specific to reduce false positives
      if (value.length >= 20 && value.length <= 256) {
        // AWS API keys
        if (/^AKIA[0-9A-Z]{16}$/i.test(value)) {
          patterns.push({
            type: 'security',
            pattern: 'aws_api_key',
            severity: 'high',
            line: path.node.loc.start.line,
            column: path.node.loc.start.column,
            message: 'AWS API key detected',
            code: lines[path.node.loc.start.line - 1]
          });
        }
        // Generic API key pattern (more conservative)
        else if (/^[a-z0-9_-]{32,64}$/i.test(value) && 
                 /api|key|token|secret/i.test(path.parent.key?.name || '')) {
          patterns.push({
            type: 'security',
            pattern: 'potential_api_key',
            severity: 'medium',
            line: path.node.loc.start.line,
            column: path.node.loc.start.column,
            message: 'Potential hardcoded API key or secret',
            code: lines[path.node.loc.start.line - 1]
          });
        }
      }
      
      // Password / credential patterns. AST-context-aware to avoid
      // firing on logger strings like console.error('Password reset
      // error:', err). We require BOTH:
      //   1. The string is being assigned to a credential-named
      //      identifier (variable, object property, or member),
      //      via AST parent inspection.
      //   2. The string value itself plausibly looks like a credential
      //      (no whitespace, mixed character classes, reasonable length).
      // This trades the prior regex-on-value heuristic, which fired on
      // any string containing "password:" or "secret=" — including log
      // strings and JSON keys in code comments — for a context check
      // that catches real assignments and dramatically fewer FPs.
      const credIdentName = identifierAssignedTo(path);
      if (credIdentName && isCredentialIdentifierName(credIdentName)
          && looksLikeCredentialValue(value)) {
        patterns.push({
          type: 'security',
          pattern: 'hardcoded_password',
          severity: 'high',
          line: path.node.loc.start.line,
          column: path.node.loc.start.column,
          message: `Potential hardcoded credential assigned to "${credIdentName}"`,
          code: lines[path.node.loc.start.line - 1]
        });
      }
    },
    
    // Quality patterns
    FunctionDeclaration(path) {
      const node = path.node;
      
      // Large function detection
      if (node.body && node.body.body && node.body.body.length > 50) {
        patterns.push({
          type: 'quality',
          pattern: 'large_function',
          severity: 'medium',
          line: node.loc.start.line,
          column: node.loc.start.column,
          message: `Function is too large (${node.body.body.length} statements)`,
          code: lines[node.loc.start.line - 1]
        });
      }
      
      // Too many parameters
      if (node.params && node.params.length > 7) {
        patterns.push({
          type: 'quality',
          pattern: 'too_many_parameters',
          severity: 'medium',
          line: node.loc.start.line,
          column: node.loc.start.column,
          message: `Function has too many parameters (${node.params.length})`,
          code: lines[node.loc.start.line - 1]
        });
      }
    },
    
    // TODO/FIXME comments
    enter(path) {
      if (path.node.leadingComments) {
        path.node.leadingComments.forEach(comment => {
          const text = comment.value.toLowerCase();
          if (text.includes('todo') || text.includes('fixme') || text.includes('hack')) {
            const type = text.includes('fixme') ? 'fixme' : 
                        text.includes('hack') ? 'hack' : 'todo';
            patterns.push({
              type: 'todo',
              pattern: `${type}_comment`,
              severity: type === 'fixme' ? 'medium' : 'low',
              line: comment.loc.start.line,
              column: comment.loc.start.column,
              message: `${type.toUpperCase()} comment found`,
              code: lines[comment.loc.start.line - 1]
            });
          }
        });
      }
    }
  });
  
  return patterns;
}

/**
 * Calculate code metrics
 */
function calculateMetrics(ast, content) {
  const metrics = {
    lines_of_code: content.split('\n').length,
    functions: 0,
    classes: 0,
    imports: 0,
    complexity: 0
  };
  
  traverse(ast, {
    FunctionDeclaration() { metrics.functions++; },
    FunctionExpression() { metrics.functions++; },
    ArrowFunctionExpression() { metrics.functions++; },
    ClassDeclaration() { metrics.classes++; },
    ImportDeclaration() { metrics.imports++; },
    IfStatement() { metrics.complexity++; },
    WhileStatement() { metrics.complexity++; },
    ForStatement() { metrics.complexity++; },
    SwitchStatement() { metrics.complexity++; }
  });
  
  return metrics;
}

/**
 * Main execution
 */
function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.error('Usage: babel_parser.js <file1> [file2] ...');
    process.exit(1);
  }
  
  const results = [];
  
  for (const filePath of args) {
    if (!fs.existsSync(filePath)) {
      results.push({
        file: filePath,
        success: false,
        error: 'File not found'
      });
      continue;
    }
    
    try {
      const result = parseFile(filePath);
      // Remove AST from output to reduce size (we only need patterns and metrics)
      delete result.ast;
      results.push(result);
    } catch (error) {
      results.push({
        file: filePath,
        success: false,
        error: error.message
      });
    }
  }
  
  // Output JSON for Python consumption
  console.log(JSON.stringify(results, null, 2));
}

if (require.main === module) {
  main();
}

module.exports = {
  parseFile,
  extractPatterns,
  calculateMetrics,
  // Exported for unit testing.
  identifierAssignedTo,
  isCredentialIdentifierName,
  looksLikeCredentialValue,
};