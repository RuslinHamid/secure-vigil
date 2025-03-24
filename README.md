# Secure Vigil

A comprehensive code security analysis platform that helps developers identify and fix security vulnerabilities in their code.

## Features

- **Comprehensive Analysis**: Advanced code scanning to detect various types of vulnerabilities
- **Smart Mitigation**: AI-powered code suggestions and automatic mitigation generation
- **Detailed Reports**: Generate comprehensive PDF reports with vulnerability details
- **Real-time Analysis**: Instant code analysis with immediate feedback
- **Code Comparison**: Side-by-side comparison of original and mitigated code
- **Report Sharing**: Easy sharing of security reports via email

## Supported Technologies

- Python
- Java
- JavaScript
- C/C++
- PHP
- HTML
- Ruby

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/secure-vigil.git
cd secure-vigil
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create necessary directories:
```bash
mkdir -p uploads security_reports
```

5. Set up configuration:
```bash
cp config.ini.example config.ini
# Edit config.ini with your settings
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your browser and navigate to `http://localhost:5000`

3. Upload your code file for analysis

4. Review the security analysis results and recommendations

## Security Features

- Input validation and sanitization
- File upload security
- Session management
- XSS protection
- CSRF protection
- Secure headers
- Rate limiting
- Error handling
- Logging

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- OWASP for vulnerability patterns and mitigation strategies
- Flask framework and its extensions
- Bootstrap for the UI components
- Chart.js for data visualization


