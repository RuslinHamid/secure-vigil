import java.io.*;
import java.sql.*;
import java.util.Base64;
import javax.servlet.http.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Vulnerable extends HttpServlet {
    // Hardcoded encryption key (vulnerability)
    private static final String ENCRYPTION_KEY = "MySuperSecretKey";
    
    // SQL Injection Vulnerability
    public ResultSet getUser(String username) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "password");
            // Vulnerable SQL query
            String query = "SELECT * FROM users WHERE username = '" + username + "'";
            Statement stmt = conn.createStatement();
            return stmt.executeQuery(query);
        } catch (SQLException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // XSS Vulnerability
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        try {
            String userInput = request.getParameter("input");
            PrintWriter out = response.getWriter();
            // Vulnerable XSS
            out.println("<html><body>Welcome, " + userInput + "!</body></html>");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // Path Traversal Vulnerability
    public String readFile(String fileName) {
        try {
            // Vulnerable file access
            FileReader fr = new FileReader(fileName);
            BufferedReader br = new BufferedReader(fr);
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                content.append(line);
            }
            return content.toString();
        } catch (IOException e) {
            return "Error reading file";
        }
    }
    
    // Weak Encryption Implementation
    public String encryptData(String data) {
        try {
            // Using weak encryption
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            SecretKeySpec key = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "DES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
        } catch (Exception e) {
            return null;
        }
    }
    
    // Command Injection Vulnerability
    public String executeCommand(String command) {
        try {
            // Vulnerable command execution
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            return output.toString();
        } catch (IOException e) {
            return "Error executing command";
        }
    }
    
    // Null Pointer Vulnerability
    public void processUser(String userId) {
        User user = null;
        // Vulnerable null pointer access
        if (userId.equals("admin")) {
            System.out.println("Admin user: " + user.getName());
        }
    }
    
    // Inner class with missing private data
    public class User {
        public String name;  // Should be private
        public String password;  // Should be private
        
        public String getName() {
            return name;
        }
    }
} 