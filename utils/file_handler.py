import os
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

def read_file_with_encoding(file_path: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Read a file with proper encoding handling.
    Returns a tuple of (content, encoding_used) or (None, None) if there's an error.
    """
    try:
        # Ensure the file exists
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None, None
            
        # Read the file content in binary mode
        with open(file_path, 'rb') as f:
            content = f.read()
            
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        last_error = None
        
        for encoding in encodings:
            try:
                decoded_content = content.decode(encoding)
                logger.info(f"Successfully decoded {file_path} using {encoding} encoding")
                return decoded_content, encoding
            except UnicodeDecodeError as e:
                last_error = e
                logger.warning(f"Failed to decode {file_path} using {encoding} encoding: {str(e)}")
                continue
                
        # If all encodings fail, use latin-1 as a last resort
        decoded_content = content.decode('latin-1', errors='replace')
        logger.warning(f"Using latin-1 encoding with replacement for {file_path}")
        return decoded_content, 'latin-1'
        
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        return None, None

def get_file_language(file_path: str) -> str:
    """
    Determine the programming language based on file extension.
    Returns the language name or 'plaintext' if unknown.
    """
    file_ext = os.path.splitext(file_path)[1].lower()
    language_map = {
        '.php': 'php',
        '.py': 'python',
        '.js': 'javascript',
        '.html': 'html',
        '.css': 'css',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.cs': 'csharp',
        '.rb': 'ruby',
        '.go': 'go',
        '.rs': 'rust',
        '.swift': 'swift',
        '.kt': 'kotlin',
        '.ts': 'typescript',
        '.sql': 'sql',
        '.xml': 'xml',
        '.json': 'json',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.md': 'markdown',
        '.txt': 'plaintext'
    }
    
    return language_map.get(file_ext, 'plaintext') 