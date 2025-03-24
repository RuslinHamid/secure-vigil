import subprocess
import json
import os
import logging
from typing import Dict, List, Any
from datetime import datetime
import bandit
import safety
import pylint
import re

logger = logging.getLogger(__name__)

class SecurityVerifier:
    def __init__(self, report_dir=None):
        """Initialize the SecurityVerifier with necessary tools and configurations."""
        self.tools = {
            'bandit': self._run_bandit,
            'safety': self._run_safety,
            'pylint': self._run_pylint,
            'custom': self._run_custom_checks
        }
        # Set default report directory if none provided
        self.report_dir = report_dir or 'static/security_reports'
        os.makedirs(self.report_dir, exist_ok=True)

    def verify_mitigations(self, original_code: str, mitigated_code: str, language: str) -> Dict[str, Any]:
        """Verify that mitigations are effective by comparing original and mitigated code."""
        try:
            results = {
                'timestamp': datetime.now().isoformat(),
                'language': language,
                'original_vulnerabilities': self._find_vulnerabilities(original_code, language),
                'mitigated_vulnerabilities': self._find_vulnerabilities(mitigated_code, language),
                'security_improvements': [],
                'remaining_issues': []
            }

            # Compare vulnerabilities
            original_vulns = set(v['type'] for v in results['original_vulnerabilities'])
            mitigated_vulns = set(v['type'] for v in results['mitigated_vulnerabilities'])
            
            # Identify improvements
            fixed_vulns = original_vulns - mitigated_vulns
            for vuln_type in fixed_vulns:
                results['security_improvements'].append({
                    'type': vuln_type,
                    'status': 'fixed',
                    'details': f'Successfully mitigated {vuln_type} vulnerabilities'
                })

            # Identify remaining issues
            remaining_vulns = mitigated_vulns
            for vuln_type in remaining_vulns:
                results['remaining_issues'].append({
                    'type': vuln_type,
                    'status': 'needs_review',
                    'details': f'Potential {vuln_type} vulnerabilities still present'
                })

            return results
        except Exception as e:
            logger.error(f"Error verifying mitigations: {str(e)}")
            return {'error': str(e)}

    def find_remaining_vulnerabilities(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Find any remaining vulnerabilities in the code."""
        try:
            # Run all security tools
            results = []
            for tool_name, tool_func in self.tools.items():
                try:
                    tool_results = tool_func(code, language)
                    results.extend(tool_results)
                except Exception as e:
                    logger.error(f"Error running {tool_name}: {str(e)}")

            # Deduplicate results
            unique_results = self._deduplicate_results(results)
            return unique_results
        except Exception as e:
            logger.error(f"Error finding vulnerabilities: {str(e)}")
            return []

    def ensure_code_quality(self, code: str, language: str) -> Dict[str, Any]:
        """Ensure code quality and security best practices."""
        try:
            quality_metrics = {
                'timestamp': datetime.now().isoformat(),
                'language': language,
                'metrics': {},
                'recommendations': []
            }

            # Run code quality checks
            if language == 'python':
                quality_metrics['metrics'].update(self._run_python_quality_checks(code))
            elif language == 'javascript':
                quality_metrics['metrics'].update(self._run_javascript_quality_checks(code))
            elif language == 'php':
                quality_metrics['metrics'].update(self._run_php_quality_checks(code))

            # Generate recommendations
            quality_metrics['recommendations'] = self._generate_quality_recommendations(
                quality_metrics['metrics']
            )

            return quality_metrics
        except Exception as e:
            logger.error(f"Error ensuring code quality: {str(e)}")
            return {'error': str(e)}

    def generate_security_report(self, code: str, language: str, file_path: str) -> str:
        """Generate a detailed security report."""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'file_path': file_path,
                'language': language,
                'vulnerabilities': self.find_remaining_vulnerabilities(code, language),
                'quality_metrics': self.ensure_code_quality(code, language),
                'security_score': self._calculate_security_score(code, language),
                'recommendations': []
            }

            # Generate recommendations based on findings
            report['recommendations'] = self._generate_security_recommendations(report)

            # Save report to file with a unique name based on timestamp and original filename
            base_filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_filename = f"security_report_{base_filename}_{timestamp}.json"
            report_path = os.path.join(self.report_dir, report_filename)
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)

            return report_path
        except Exception as e:
            logger.error(f"Error generating security report: {str(e)}")
            return None

    def _run_bandit(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Run Bandit security checks."""
        if language != 'python':
            return []

        try:
            # Create temporary file with code
            with open('temp_code.py', 'w') as f:
                f.write(code)

            # Run Bandit
            result = subprocess.run(['bandit', '-r', 'temp_code.py', '-f', 'json'], 
                                 capture_output=True, text=True)
            
            # Clean up
            os.remove('temp_code.py')

            # Parse results
            if result.returncode == 0:
                return []
            return json.loads(result.stdout)
        except Exception as e:
            logger.error(f"Error running Bandit: {str(e)}")
            return []

    def _run_safety(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Run Safety dependency checks."""
        if language != 'python':
            return []

        try:
            result = subprocess.run(['safety', 'check'], capture_output=True, text=True)
            if result.returncode == 0:
                return []
            return self._parse_safety_output(result.stdout)
        except Exception as e:
            logger.error(f"Error running Safety: {str(e)}")
            return []

    def _run_pylint(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Run Pylint code quality checks."""
        if language != 'python':
            return []

        try:
            # Create temporary file with code
            with open('temp_code.py', 'w') as f:
                f.write(code)

            # Run Pylint
            result = subprocess.run(['pylint', 'temp_code.py', '--output-format=json'], 
                                 capture_output=True, text=True)
            
            # Clean up
            os.remove('temp_code.py')

            # Parse results
            return json.loads(result.stdout)
        except Exception as e:
            logger.error(f"Error running Pylint: {str(e)}")
            return []

    def _run_custom_checks(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Run custom security checks based on language."""
        results = []
        
        # Language-specific patterns
        patterns = {
            'python': {
                'eval_usage': r'eval\s*\(',
                'exec_usage': r'exec\s*\(',
                'subprocess_shell': r'subprocess\.run\(.*shell=True',
                'pickle_usage': r'pickle\.(load|loads|dump|dumps)',
                'yaml_load': r'yaml\.(load|load_all)',
                'temp_file': r'tempfile\.NamedTemporaryFile\(.*delete=False'
            },
            'javascript': {
                'eval_usage': r'eval\s*\(',
                'innerHTML': r'innerHTML\s*=',
                'document_write': r'document\.write\(',
                'setTimeout_string': r'setTimeout\s*\(\s*[\'"]',
                'setInterval_string': r'setInterval\s*\(\s*[\'"]'
            },
            'php': {
                'eval_usage': r'eval\s*\(',
                'shell_exec': r'shell_exec\s*\(',
                'system': r'system\s*\(',
                'exec': r'exec\s*\(',
                'passthru': r'passthru\s*\('
            }
        }

        if language in patterns:
            for vuln_type, pattern in patterns[language].items():
                matches = re.finditer(pattern, code)
                for match in matches:
                    line_number = code[:match.start()].count('\n') + 1
                    results.append({
                        'type': vuln_type,
                        'line_number': line_number,
                        'severity': 'High',
                        'description': f'Potential security vulnerability: {vuln_type}'
                    })

        return results

    def _deduplicate_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate vulnerability results."""
        seen = set()
        unique_results = []
        
        for result in results:
            key = (result.get('type'), result.get('line_number'))
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        return unique_results

    def _calculate_security_score(self, code: str, language: str) -> float:
        """Calculate a security score based on various metrics."""
        try:
            vulnerabilities = self.find_remaining_vulnerabilities(code, language)
            quality_metrics = self.ensure_code_quality(code, language)
            
            # Base score
            score = 100.0
            
            # Deduct points for vulnerabilities
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'Medium')
                if severity == 'High':
                    score -= 20
                elif severity == 'Medium':
                    score -= 10
                else:
                    score -= 5
            
            # Deduct points for quality issues
            if 'metrics' in quality_metrics:
                metrics = quality_metrics['metrics']
                if 'complexity' in metrics and metrics['complexity'] > 10:
                    score -= 5
                if 'maintainability' in metrics and metrics['maintainability'] < 0.7:
                    score -= 5
            
            # Ensure score is between 0 and 100
            return max(0, min(100, score))
        except Exception as e:
            logger.error(f"Error calculating security score: {str(e)}")
            return 0.0

    def _generate_security_recommendations(self, report: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on report findings."""
        recommendations = []
        
        # Add recommendations based on vulnerabilities
        for vuln in report.get('vulnerabilities', []):
            vuln_type = vuln.get('type', '')
            if 'injection' in vuln_type.lower():
                recommendations.append(f"Implement input validation and sanitization for {vuln_type}")
            elif 'xss' in vuln_type.lower():
                recommendations.append("Use proper output encoding to prevent XSS attacks")
            elif 'sql' in vuln_type.lower():
                recommendations.append("Use parameterized queries or prepared statements")
        
        # Add recommendations based on quality metrics
        metrics = report.get('quality_metrics', {}).get('metrics', {})
        if metrics.get('complexity', 0) > 10:
            recommendations.append("Reduce code complexity to improve maintainability")
        if metrics.get('maintainability', 1) < 0.7:
            recommendations.append("Improve code maintainability by reducing dependencies")
        
        return recommendations

    def _generate_quality_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """Generate code quality recommendations based on metrics."""
        recommendations = []
        
        if metrics.get('complexity', 0) > 10:
            recommendations.append("Consider breaking down complex functions into smaller, more manageable pieces")
        
        if metrics.get('maintainability', 1) < 0.7:
            recommendations.append("Review and reduce code dependencies to improve maintainability")
        
        if metrics.get('test_coverage', 0) < 0.8:
            recommendations.append("Increase test coverage to improve code reliability")
        
        return recommendations

    def _parse_safety_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Safety tool output into structured format."""
        results = []
        for line in output.split('\n'):
            if '|' in line:
                parts = line.split('|')
                if len(parts) >= 3:
                    results.append({
                        'type': 'Dependency Vulnerability',
                        'package': parts[0].strip(),
                        'version': parts[1].strip(),
                        'description': parts[2].strip(),
                        'severity': 'High'
                    })
        return results

    def _find_vulnerabilities(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Find vulnerabilities in the code using language-specific patterns."""
        vulnerabilities = []
        
        # Language-specific patterns
        patterns = {
            'php': {
                'sql_injection': r'mysql_query\((.*?)\)|mysqli_query\((.*?)\)|PDO::query\((.*?)\)',
                'xss': r'echo\s+(?!htmlspecialchars)',
                'command_injection': r'shell_exec\((.*?)\)|system\((.*?)\)|exec\((.*?)\)',
                'file_inclusion': r'include\s*\((.*?)\)|require\s*\((.*?)\)',
                'eval_usage': r'eval\((.*?)\)',
                'file_upload': r'move_uploaded_file\((.*?)\)'
            },
            'python': {
                'sql_injection': r'execute\((.*?)\)|executemany\((.*?)\)',
                'command_injection': r'os\.system\((.*?)\)|subprocess\.call\((.*?)\)',
                'eval_usage': r'eval\((.*?)\)|exec\((.*?)\)',
                'pickle_usage': r'pickle\.(load|loads)',
                'yaml_load': r'yaml\.(load|load_all)'
            },
            'javascript': {
                'xss': r'innerHTML\s*=|document\.write\(',
                'eval_usage': r'eval\((.*?)\)',
                'setTimeout_string': r'setTimeout\s*\(\s*[\'"]',
                'setInterval_string': r'setInterval\s*\(\s*[\'"]'
            }
        }

        if language in patterns:
            for vuln_type, pattern in patterns[language].items():
                matches = re.finditer(pattern, code)
                for match in matches:
                    line_number = code[:match.start()].count('\n') + 1
                    vulnerabilities.append({
                        'type': vuln_type,
                        'line_number': line_number,
                        'pattern': match.group(0),
                        'severity': 'High',
                        'description': f'Potential {vuln_type} vulnerability detected'
                    })

        return vulnerabilities

    def _run_php_quality_checks(self, code: str) -> Dict[str, Any]:
        """Run PHP-specific code quality checks."""
        metrics = {
            'complexity': self._calculate_complexity(code),
            'maintainability': self._calculate_maintainability(code),
            'test_coverage': 0.0,  # Would need PHPUnit for actual coverage
            'security_score': self._calculate_security_score(code, 'php')
        }
        return metrics

    def _run_python_quality_checks(self, code: str) -> Dict[str, Any]:
        """Run Python-specific code quality checks."""
        metrics = {
            'complexity': self._calculate_complexity(code),
            'maintainability': self._calculate_maintainability(code),
            'test_coverage': 0.0,  # Would need coverage.py for actual coverage
            'security_score': self._calculate_security_score(code, 'python')
        }
        return metrics

    def _run_javascript_quality_checks(self, code: str) -> Dict[str, Any]:
        """Run JavaScript-specific code quality checks."""
        metrics = {
            'complexity': self._calculate_complexity(code),
            'maintainability': self._calculate_maintainability(code),
            'test_coverage': 0.0,  # Would need Jest for actual coverage
            'security_score': self._calculate_security_score(code, 'javascript')
        }
        return metrics

    def _calculate_complexity(self, code: str) -> int:
        """Calculate code complexity based on control structures."""
        complexity = 1  # Base complexity
        complexity += len(re.findall(r'\bif\b', code))
        complexity += len(re.findall(r'\bfor\b', code))
        complexity += len(re.findall(r'\bwhile\b', code))
        complexity += len(re.findall(r'\bswitch\b', code))
        complexity += len(re.findall(r'\bcatch\b', code))
        return complexity

    def _calculate_maintainability(self, code: str) -> float:
        """Calculate code maintainability score."""
        # Simple maintainability calculation based on code length and complexity
        complexity = self._calculate_complexity(code)
        lines = len(code.splitlines())
        maintainability = 1.0 - (complexity / (lines + 1))  # Avoid division by zero
        return max(0.0, min(1.0, maintainability)) 