# Secure Vigil

A comprehensive code security analysis platform that helps developers identify and fix security vulnerabilities in their code. The platform uses advanced AI-powered analysis to detect vulnerabilities and provide actionable mitigation strategies.

## Features

- **Comprehensive Analysis**: Advanced code scanning to detect various types of vulnerabilities including:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Local/Remote File Inclusion
  - Path Traversal
  - Insecure File Uploads
  - Cryptographic Vulnerabilities
  - Shell Command Vulnerabilities
  - And more...

- **Smart Mitigation**: 
  - AI-powered code suggestions using Google's Gemini API
  - Automatic mitigation generation
  - Side-by-side code comparison
  - Real-time vulnerability fixes

- **Detailed Reports**: 
  - Comprehensive PDF reports
  - Vulnerability details and risk assessment
  - Mitigation recommendations
  - Code quality metrics
  - Security improvement tracking

- **Real-time Analysis**:
  - Instant code scanning
  - Live vulnerability detection
  - Immediate feedback
  - Interactive code editor

- **Modern UI/UX**:
  - Matrix-style theme
  - Responsive design
  - Interactive visualizations
  - User-friendly interface

## Supported Technologies

- Python
- Java
- JavaScript
- C/C++
- PHP
- HTML
- Ruby

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- SendGrid API key (for email functionality)
- Google Gemini API key (for AI-powered analysis)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Gokkulamoorthy/secure-vigil.git
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

5. Set up environment variables:
   - Create a `.env` file in the root directory
   - Add the following variables:
```env
SENDGRID_API_KEY=your_sendgrid_api_key_here
MAIL_DEFAULT_SENDER=your_verified_email_here
GEMINI_API_KEY=your_gemini_api_key_here
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your browser and navigate to `http://localhost:5000`

3. Use the platform:
   - Upload your code file or paste code directly
   - Select the programming language
   - Click "Analyze" to start the security scan
   - Review vulnerabilities and suggested fixes
   - Compare original and mitigated code
   - Download or email the security report

## Security Features

- **Input Validation**:
  - File type verification
  - Size limits
  - Content validation

- **Access Control**:
  - Rate limiting
  - Session management
  - Secure file operations

- **Data Protection**:
  - Secure file handling
  - Environment variable protection
  - Sensitive data encryption

- **Error Handling**:
  - Detailed logging
  - Graceful error recovery
  - User-friendly error messages

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
- Google Gemini API for AI-powered analysis
- Monaco Editor for code editing
- SendGrid for email functionality
