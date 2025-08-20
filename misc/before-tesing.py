testcases = [
    {
        "code": 'public class Example8 {\n    public static void main(String[] args) {\n        String password = "secret";\n        System.out.println(password);\n    }\n}',
        "expected": "VULNERABLE",
        "description": "Hardcoded credentials vulnerability",
    },
    {
        "code": 'public class Example17 {\n    public static void main(String[] args) throws Exception {\n        String fileName = args[0];\n        if (!fileName.matches("[a-zA-Z0-9]+\\\\.txt")) {\n            throw new IllegalArgumentException("Invalid file name");\n        }\n        File file = new File("uploads/" + fileName);\n        FileInputStream fis = new FileInputStream(file);\n    }\n}',
        "expected": "NOT_VULNERABLE",
        "description": "Validated file name prevents path traversal",
    },
    {
        "code": 'public class Example23 {\n    public void processRequest(HttpServletRequest request) throws Exception {\n        String token = request.getParameter("token");\n        String storedToken = System.getenv("AUTH_TOKEN");\n        if (token.equals(storedToken)) {\n            // Grant access\n        }\n    }\n}',
        "expected": "NOT_VULNERABLE",
        "description": "Secure token comparison using environment variable",
    },
    {
        "code": 'public class Example30 {\n    public String hashPassword(String password) throws Exception {\n        MessageDigest md = MessageDigest.getInstance("SHA-1");\n        return new String(md.digest(password.getBytes()));\n    }\n}',
        "expected": "VULNERABLE",
        "description": "Using weak hashing algorithm (SHA-1) for passwords",
    },
    {
        "code": "public class Example61 {\n    public void setHeaders(HttpServletResponse response) {\n        // No security headers set\n    }\n}",
        "expected": "VULNERABLE",
        "description": "Missing security headers allowing XSS and other attacks",
    },
    {
        "code": "public class Example86 {\n    public boolean compareSecrets(String a, String b) {\n        return a.equals(b);\n    }\n}",
        "expected": "VULNERABLE",
        "description": "Timing attack vulnerability in string comparison",
    },
    {
        "code": "public class Example101 {\n    public void execUserCommand(String cmd) throws IOException {\n        Runtime.getRuntime().exec(cmd);\n    }\n}",
        "expected": "VULNERABLE",
        "description": "Command injection vulnerability by executing user-supplied command",
    },
    {
        "code": 'public class Example102 {\n    public void queryUser(Connection conn, String id) throws SQLException {\n        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\n        stmt.setString(1, id);\n        stmt.executeQuery();\n    }\n}',
        "expected": "NOT_VULNERABLE",
        "description": "Secure SQL query using prepared statement",
    },
    {
        "code": 'public class Example103 {\n    public void queryUser(Connection conn, String id) throws SQLException {\n        Statement stmt = conn.createStatement();\n        stmt.execute("SELECT * FROM users WHERE id = " + id);\n    }\n}',
        "expected": "VULNERABLE",
        "description": "SQL injection vulnerability due to unvalidated concatenation",
    },
    {
        "code": 'public class Example104 {\n    public String hash(String password) throws Exception {\n        MessageDigest md = MessageDigest.getInstance("MD5");\n        return Base64.getEncoder().encodeToString(md.digest(password.getBytes()));\n    }\n}',
        "expected": "VULNERABLE",
        "description": "Weak hash algorithm MD5 used for password hashing",
    },
    {
        "code": 'public class Example105 {\n    public String hash(String password) throws Exception {\n        MessageDigest md = MessageDigest.getInstance("SHA-256");\n        return Base64.getEncoder().encodeToString(md.digest(password.getBytes()));\n    }\n}',
        "expected": "NOT_VULNERABLE",
        "description": "Secure hashing using SHA-256",
    },
    {
        "code": 'public class Example106 {\n    public void render(HttpServletRequest req, HttpServletResponse res) throws IOException {\n        String input = req.getParameter("q");\n        res.getWriter().write(input);\n    }\n}',
        "expected": "VULNERABLE",
        "description": "XSS vulnerability due to direct reflection of input",
    },
    {
        "code": 'public class Example107 {\n    public void render(HttpServletRequest req, HttpServletResponse res) throws IOException {\n        String input = req.getParameter("q");\n        String safe = org.apache.commons.text.StringEscapeUtils.escapeHtml4(input);\n        res.getWriter().write(safe);\n    }\n}',
        "expected": "NOT_VULNERABLE",
        "description": "Escaped output to prevent XSS",
    },
    {
        "code": 'public class Example108 {\n    public void openFile(String name) throws IOException {\n        File file = new File("uploads/" + name);\n        new FileInputStream(file);\n    }\n}',
        "expected": "VULNERABLE",
        "description": "Path traversal vulnerability by allowing arbitrary file name",
    },
    {
        "code": 'public class Example109 {\n    public void openFile(String name) throws IOException {\n        if (!name.matches("[a-zA-Z0-9]+\\\\.txt")) throw new IllegalArgumentException();\n        File file = new File("uploads/" + name);\n        new FileInputStream(file);\n    }\n}',
        "expected": "NOT_VULNERABLE",
        "description": "Validated file name prevents path traversal",
    },
    {
        "code": "public class Example110 {\n    public boolean isSame(String a, String b) {\n        return a.equals(b);\n    }\n}",
        "expected": "VULNERABLE",
        "description": "Potential timing attack due to standard equals comparison",
    },
    {
        "code": "public class Example111 {\n    public boolean isSame(String a, String b) {\n        return MessageDigest.isEqual(a.getBytes(), b.getBytes());\n    }\n}",
        "expected": "NOT_VULNERABLE",
        "description": "Safe constant-time comparison to avoid timing attack",
    },
    {
        "code": 'public class Example112 {\n    public void setSecurityHeaders(HttpServletResponse response) {\n        response.setHeader("Content-Security-Policy", "default-src \'self\'");\n        response.setHeader("X-Content-Type-Options", "nosniff");\n        response.setHeader("X-Frame-Options", "DENY");\n    }\n}',
        "expected": "NOT_VULNERABLE",
        "description": "Proper security headers set",
    },
    {
        "code": "public class Example113 {\n    public void setSecurityHeaders(HttpServletResponse response) {\n        // no headers set intentionally\n    }\n}",
        "expected": "VULNERABLE",
        "description": "Missing security headers exposing app to XSS/Clickjacking",
    },
    {
        "code": 'public class Example114 {\n    public void connect() {\n        String apiKey = "ABCD1234SECRET";\n        System.out.println(apiKey);\n    }\n}',
        "expected": "VULNERABLE",
        "description": "Hardcoded API key vulnerability",
    },
    {
        "code": 'public class Example115 {\n    public void connect() {\n        String apiKey = System.getenv("API_KEY");\n        System.out.println(apiKey);\n    }\n}',
        "expected": "NOT_VULNERABLE",
        "description": "API key from environment variable (safer practice)",
    },
    {
        "code": 'public class Test1 {\n    public static void main(String[] args) {\n        String apiKey = "ABCD1234";\n        System.out.println("Using API key: " + apiKey);\n    }\n}',
        "expected": "VULNERABLE",
        "description": "Hardcoded API key",
    },
    {
        "code": 'public class Test2 {\n    private final String DB_PASSWORD = "pass123";\n    public void connect() {\n        System.out.println("Connecting with password: " + DB_PASSWORD);\n    }\n}',
        "expected": "VULNERABLE",
        "description": "Hardcoded database password",
    },
    {
        "code": 'class Secrets {\n    static {\n        System.setProperty("secret", "mysecretpass");\n    }\n}',
        "expected": "VULNERABLE",
        "description": "Hardcoded secret via system property",
    },
    {
        "code": 'public class SafeToken {\n    public boolean validateToken(String input) {\n        String envToken = System.getenv("AUTH_TOKEN");\n        return input.equals(envToken);\n    }\n}',
        "expected": "NOT_VULNERABLE",
        "description": "Secure token comparison using environment variable",
    },
    {
        "code": 'String stored = System.getProperty("token");\nif (MessageDigest.isEqual(input.getBytes(), stored.getBytes())) {\n    grantAccess();\n}',
        "expected": "NOT_VULNERABLE",
        "description": "Constant-time secure string comparison",
    },
    {
        "code": 'public class UnsafeFile {\n    public void read(String filename) {\n        new FileInputStream("/data/" + filename);\n    }\n}',
        "expected": "VULNERABLE",
        "description": "Unvalidated file name allows path traversal",
    },
    {
        "code": 'public class SafeFile {\n    public void read(String filename) {\n        if (!filename.matches("[a-zA-Z0-9_]+\\.txt")) {\n            throw new IllegalArgumentException();\n        }\n        new FileInputStream("/safe_dir/" + filename);\n    }\n}',
        "expected": "NOT_VULNERABLE",
        "description": "Validated file name prevents path traversal",
    },
    {
        "code": "public boolean verifyPin(String input, String correct) {\n    return input.equals(correct);\n}",
        "expected": "VULNERABLE",
        "description": "Timing attack possible due to string equality",
    },
    {
        "code": "if (userHash.equals(dbHash)) { allow(); }",
        "expected": "VULNERABLE",
        "description": "Direct string comparison vulnerable to timing attacks",
    },
    {
        "code": 'public String hash(String pass) {\n    MessageDigest md = MessageDigest.getInstance("MD5");\n    return Base64.getEncoder().encodeToString(md.digest(pass.getBytes()));\n}',
        "expected": "VULNERABLE",
        "description": "Using weak hashing algorithm MD5",
    },
    {
        "code": "SecureRandom random = new SecureRandom();\nbyte[] nonce = new byte[16];\nrandom.nextBytes(nonce);",
        "expected": "NOT_VULNERABLE",
        "description": "Use of cryptographically strong random generator",
    },
    {
        "code": 'Runtime.getRuntime().exec("ping " + userInput);',
        "expected": "VULNERABLE",
        "description": "User input directly used in command execution",
    },
    {
        "code": 'ProcessBuilder pb = new ProcessBuilder("sh", "-c", "echo " + userCmd);\npb.start();',
        "expected": "VULNERABLE",
        "description": "Command injection via shell execution",
    },
    {
        "code": 'Process p = Runtime.getRuntime().exec(new String[]{"ls", "-la"});',
        "expected": "NOT_VULNERABLE",
        "description": "Safe use of hardcoded command",
    },
    {
        "code": 'Statement stmt = connection.createStatement();\nResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + id);',
        "expected": "VULNERABLE",
        "description": "Concatenating user input into SQL query",
    },
    {
        "code": 'PreparedStatement ps = connection.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setString(1, id);\nps.executeQuery();',
        "expected": "NOT_VULNERABLE",
        "description": "Parameterized query prevents SQL injection",
    },
    {
        "code": "public void setHeaders(HttpServletResponse response) {\n    // No security headers set\n}",
        "expected": "VULNERABLE",
        "description": "Missing security headers allowing XSS and other attacks",
    },
    {
        "code": 'response.setHeader("Content-Security-Policy", "default-src \'self\'");',
        "expected": "NOT_VULNERABLE",
        "description": "Security header set correctly",
    },
    {
        "code": 'if (input != null && input.equals("admin")) grantAdmin();',
        "expected": "VULNERABLE",
        "description": "Hardcoded credential check",
    },
    {
        "code": 'response.setHeader("X-Frame-Options", "DENY");',
        "expected": "NOT_VULNERABLE",
        "description": "Security header prevents clickjacking",
    },
    {
        "code": 'try (InputStream is = getClass().getResourceAsStream("/config/secrets.properties")) {}',
        "expected": "NOT_VULNERABLE",
        "description": "Reading secrets from resource stream securely",
    },
    {
        "code": 'new File(System.getProperty("user.home") + "/.app/config.txt");',
        "expected": "NOT_VULNERABLE",
        "description": "Safe file access using system properties",
    },
    {
        "code": "return password.hashCode() == storedHash;",
        "expected": "VULNERABLE",
        "description": "Insecure password comparison using hash code",
    },
    {
        "code": "public class Example {\n    public static void main(String[] args) {\n        byte[] buffer = new byte[10];\n        System.in.read(buffer);\n    }\n}",
        "vulnerability_type": "Buffer Overflow",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    public void transferMoney(Account from, Account to, double amount) {\n        if (from.getBalance() >= amount) {\n            from.withdraw(amount);\n            to.deposit(amount);\n        }\n    }\n}",
        "vulnerability_type": "Race Condition",
        "expected": "VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public String encrypt(String data) throws Exception {\n        Cipher cipher = Cipher.getInstance("DES");\n        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("key12345".getBytes(), "DES"));\n        byte[] encryptedData = cipher.doFinal(data.getBytes());\n        return Base64.getEncoder().encodeToString(encryptedData);\n    }\n}',
        "vulnerability_type": "Weak Encryption",
        "expected": "VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public boolean authenticate(String username, String password) {\n        return username.equals("admin") && password.equals("password");\n    }\n}',
        "vulnerability_type": "Broken Authentication",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    public void configureSecurity(SecurityConfig config) {\n        config.disableCsrfProtection();\n        config.allowAllOrigins();\n    }\n}",
        "vulnerability_type": "Security Misconfiguration",
        "expected": "VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void sendUserData(HttpServletResponse response, User user) throws IOException {\n        response.getWriter().write("User data: " + user.toString());\n    }\n}',
        "vulnerability_type": "Sensitive Data Exposure",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    public void processPayment(Payment payment) {\n        // Process payment without logging\n    }\n}",
        "vulnerability_type": "Insufficient Logging",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    public void fetchUrl(String url) throws Exception {\n        URL u = new URL(url);\n        HttpURLConnection connection = (HttpURLConnection) u.openConnection();\n        connection.getInputStream();\n    }\n}",
        "vulnerability_type": "SSRF",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    public void parseXML(String xml) throws Exception {\n        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n        DocumentBuilder builder = factory.newDocumentBuilder();\n        builder.parse(new InputSource(new StringReader(xml)));\n    }\n}",
        "vulnerability_type": "XXE",
        "expected": "VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void deleteUser(HttpServletRequest request) {\n        String userId = request.getParameter("userId");\n        userDao.delete(userId);\n    }\n}',
        "vulnerability_type": "Broken Access Control",
        "expected": "VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void processAPIRequest(HttpServletRequest request) {\n        String apiKey = request.getHeader("API-Key");\n        if (apiKey.equals("12345")) {\n            // Process request\n        }\n    }\n}',
        "vulnerability_type": "Insecure API Usage",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    public void readFile(String filePath) throws Exception {\n        File file = new File(filePath);\n        FileInputStream fis = new FileInputStream(file);\n    }\n}",
        "vulnerability_type": "Directory Traversal",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    public void processData(byte[] data) {\n        // Process data without bounds checking\n        System.out.println(new String(data));\n    }\n}",
        "vulnerability_type": "Heap Inspection",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    private static List<Object> cache = new ArrayList<>();\n    public void addToCache(Object obj) {\n        cache.add(obj);\n    }\n}",
        "vulnerability_type": "Memory Leak",
        "expected": "VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void processLargeInput(String input) {\n        // Process large input without size limits\n        String[] parts = input.split(",");\n        for (String part : parts) {\n            System.out.println(part);\n        }\n    }\n}',
        "vulnerability_type": "DoS",
        "expected": "VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void uploadFile(HttpServletRequest request) throws Exception {\n        Part filePart = request.getPart("file");\n        String fileName = filePart.getSubmittedFileName();\n        filePart.write("uploads/" + fileName);\n    }\n}',
        "vulnerability_type": "Insecure File Upload",
        "expected": "VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void sendDataOverHttp(String data) throws Exception {\n        URL url = new URL("http://example.com/api");\n        HttpURLConnection connection = (HttpURLConnection) url.openConnection();\n        connection.setRequestMethod("POST");\n        connection.getOutputStream().write(data.getBytes());\n    }\n}',
        "vulnerability_type": "Insecure Communication",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    public void validateCertificate(Certificate cert) {\n        // No validation logic\n    }\n}",
        "vulnerability_type": "Improper Certificate Validation",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    public void configureServer() {\n        Server server = new Server(8080);\n        server.setDefaultServlet(new DefaultServlet());\n        // No security configurations\n    }\n}",
        "vulnerability_type": "Insecure Default Configurations",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    public void processRequest(HttpServletRequest request) {\n        try {\n            // Process request\n        } catch (Exception e) {\n            e.printStackTrace();\n        }\n    }\n}",
        "vulnerability_type": "Improper Exception Handling",
        "expected": "VULNERABLE",
    },
    {
        "code": "public class Example {\n    public static void main(String[] args) throws IOException {\n        byte[] buffer = new byte[1024];\n        int bytesRead = System.in.read(buffer, 0, buffer.length);\n        if (bytesRead > 0) {\n            System.out.write(buffer, 0, bytesRead);\n        }\n    }\n}",
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": "public class Example {\n    public synchronized void transferMoney(Account from, Account to, double amount) {\n        if (from.getBalance() >= amount) {\n            from.withdraw(amount);\n            to.deposit(amount);\n        }\n    }\n}",
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'import javax.crypto.Cipher;\nimport javax.crypto.spec.SecretKeySpec;\nimport java.util.Base64;\n\npublic class Example {\n    public String encrypt(String data) throws Exception {\n        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n        SecretKeySpec keySpec = new SecretKeySpec("1234567890123456".getBytes(), "AES");\n        cipher.init(Cipher.ENCRYPT_MODE, keySpec);\n        byte[] encryptedData = cipher.doFinal(data.getBytes());\n        return Base64.getEncoder().encodeToString(encryptedData);\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public boolean authenticate(String username, String password) {\n        // Assume getHashedPassword retrieves the hashed password from a secure store\n        String storedHash = getHashedPassword(username);\n        String inputHash = hashPassword(password);\n        return secureCompare(storedHash, inputHash);\n    }\n\n    private String hashPassword(String password) {\n        // Implement secure hashing\n        return "hashed_password";\n    }\n\n    private boolean secureCompare(String a, String b) {\n        // Implement constant-time comparison\n        if (a.length() != b.length()) return false;\n        int result = 0;\n        for (int i = 0; i < a.length(); i++) {\n            result |= a.charAt(i) ^ b.charAt(i);\n        }\n        return result == 0;\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void configureSecurity(SecurityConfig config) {\n        config.enableCsrfProtection();\n        config.setAllowedOrigins(new String[]{"https://trusted.com"});\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void sendUserData(HttpServletResponse response, User user) throws IOException {\n        response.getWriter().write("User data: " + sanitize(user.toString()));\n    }\n\n    private String sanitize(String input) {\n        // Implement data sanitization\n        return input.replaceAll("[^a-zA-Z0-9]", "");\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    private static final Logger logger = Logger.getLogger(Example.class.getName());\n\n    public void processPayment(Payment payment) {\n        logger.info("Processing payment for user: " + payment.getUserId());\n        // Process payment\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void fetchUrl(String url) throws Exception {\n        URL u = new URL(url);\n        if (!u.getHost().equals("trusted.com")) {\n            throw new SecurityException("Invalid URL");\n        }\n        HttpURLConnection connection = (HttpURLConnection) u.openConnection();\n        connection.getInputStream();\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void parseXML(String xml) throws Exception {\n        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n        DocumentBuilder builder = factory.newDocumentBuilder();\n        builder.parse(new InputSource(new StringReader(xml)));\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void deleteUser(HttpServletRequest request) {\n        String userId = request.getParameter("userId");\n        String currentUserId = request.getSession().getAttribute("userId");\n        if (!userId.equals(currentUserId) && !isAdmin(request)) {\n            throw new SecurityException("Unauthorized access");\n        }\n        userDao.delete(userId);\n    }\n\n    private boolean isAdmin(HttpServletRequest request) {\n        // Check if user is admin\n        return false;\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void processAPIRequest(HttpServletRequest request) {\n        String apiKey = request.getHeader("API-Key");\n        if (!validateApiKey(apiKey)) {\n            throw new SecurityException("Invalid API key");\n        }\n        // Process request\n    }\n\n    private boolean validateApiKey(String apiKey) {\n        // Implement secure API key validation\n        return apiKey != null && apiKey.equals(getSecureApiKey());\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void readFile(String filePath) throws Exception {\n        File file = new File("safe_directory/" + filePath);\n        if (!file.getCanonicalPath().startsWith(new File("safe_directory").getCanonicalPath())) {\n            throw new SecurityException("Invalid file path");\n        }\n        FileInputStream fis = new FileInputStream(file);\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void processData(byte[] data) {\n        if (data.length > 1024) {\n            throw new IllegalArgumentException("Data too large");\n        }\n        System.out.println(new String(data, 0, Math.min(data.length, 1024)));\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": "public class Example {\n    private static final Map<String, Object> cache = new HashMap<>();\n    public void addToCache(String key, Object obj) {\n        if (cache.size() > 1000) {\n            cache.clear();\n        }\n        cache.put(key, obj);\n    }\n}",
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void processLargeInput(String input) {\n        if (input.length() > 1000) {\n            throw new IllegalArgumentException("Input too large");\n        }\n        String[] parts = input.split(",", 100);\n        for (String part : parts) {\n            System.out.println(part);\n        }\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void uploadFile(HttpServletRequest request) throws Exception {\n        Part filePart = request.getPart("file");\n        String fileName = filePart.getSubmittedFileName();\n        if (!fileName.endsWith(".txt")) {\n            throw new IllegalArgumentException("Only .txt files are allowed");\n        }\n        filePart.write("uploads/" + sanitizeFileName(fileName));\n    }\n\n    private String sanitizeFileName(String fileName) {\n        return fileName.replaceAll("[^a-zA-Z0-9.]", "_");\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void sendDataOverHttps(String data) throws Exception {\n        URL url = new URL("https://example.com/api");\n        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();\n        connection.setRequestMethod("POST");\n        connection.getOutputStream().write(data.getBytes());\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void validateCertificate(X509Certificate cert) throws CertificateException {\n        try {\n            cert.checkValidity();\n            // Additional validation checks\n        } catch (Exception e) {\n            throw new CertificateException("Invalid certificate");\n        }\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": "public class Example {\n    public void configureServer() {\n        Server server = new Server(8443);\n        server.setDefaultServlet(new SecureServlet());\n        server.setSecurityHandler(new SecurityHandler());\n    }\n}",
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'public class Example {\n    public void processRequest(HttpServletRequest request) {\n        try {\n            // Process request\n        } catch (Exception e) {\n            logger.error("Error processing request", e);\n            throw new ServletException("An error occurred", e);\n        }\n    }\n}',
        "vulnerability_type": "safe",
        "expected": "NOT_VULNERABLE",
    },
    {
        "code": 'String dbPassword = "p@ssw0rd123"; // Hardcoded DB password',
        "expected": "VULNERABLE",
        "description": "Hardcoded credentials in plaintext",
    },
    {
        "code": 'final String API_KEY = System.getenv("SECURE_API_KEY");',
        "expected": "NOT_VULNERABLE",
        "description": "Secure credential loading from environment variables",
    },
    {
        "code": 'String query = "DELETE FROM users WHERE id = " + userInput;',
        "expected": "VULNERABLE",
        "description": "SQL Injection in DELETE statement",
    },
    {
        "code": 'String query = "SELECT * FROM products WHERE category = ?";\nPreparedStatement stmt = conn.prepareStatement(query);\nstmt.setString(1, userInput);',
        "expected": "NOT_VULNERABLE",
        "description": "Parameterized query prevents SQLi",
    },
    {
        "code": 'Runtime.getRuntime().exec("sh -c \'" + userInput + "\'");',
        "expected": "VULNERABLE",
        "description": "Command injection via shell concatenation",
    },
    {
        "code": 'String[] cmd = {"echo", userInput};\nRuntime.getRuntime().exec(cmd);',
        "expected": "VULNERABLE",
        "description": "Unsanitized user input in command array",
    },
    {
        "code": 'response.getWriter().print("<div>" + userComment + "</div>");',
        "expected": "VULNERABLE",
        "description": "Direct user input in HTML without escaping",
    },
    {
        "code": 'response.getWriter().print("<div>" + Encode.forHtml(userComment) + "</div>");',
        "expected": "NOT_VULNERABLE",
        "description": "Proper HTML output encoding",
    },
    {
        "code": "ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\nObject obj = ois.readObject();",
        "expected": "VULNERABLE",
        "description": "Untrusted deserialization without validation",
    },
    {
        "code": "ObjectInputStream ois = new SafeObjectInputStream(request.getInputStream(), SafeClass.class);",
        "expected": "NOT_VULNERABLE",
        "description": "Deserialization with allowlist validation",
    },
    {
        "code": 'File file = new File("/var/www/uploads/" + userSuppliedFilename);',
        "expected": "VULNERABLE",
        "description": "Potential path traversal via filename",
    },
    {
        "code": 'String safeName = userSuppliedFilename.replaceAll("[^a-zA-Z0-9.-]", "_");\nFile file = new File("/var/www/uploads/", safeName);',
        "expected": "NOT_VULNERABLE",
        "description": "Filename sanitization prevents traversal",
    },
    {
        "code": 'Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");',
        "expected": "VULNERABLE",
        "description": "Weak cipher algorithm (DES) and mode (ECB)",
    },
    {
        "code": 'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\ncipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));',
        "expected": "NOT_VULNERABLE",
        "description": "Secure AES-GCM configuration",
    },
    {
        "code": "URL url = new URL(userSuppliedUrl);\nHttpURLConnection conn = (HttpURLConnection) url.openConnection();",
        "expected": "VULNERABLE",
        "description": "Unrestricted URL fetching enables SSRF",
    },
    {
        "code": 'if (userSuppliedUrl.startsWith("https://trusted-api.com/")) {\n  URL url = new URL(userSuppliedUrl);\n  HttpURLConnection conn = (HttpURLConnection) url.openConnection();\n}',
        "expected": "NOT_VULNERABLE",
        "description": "URL allowlist prevents SSRF",
    },
    {
        "code": "int sessionToken = new Random().nextInt();",
        "expected": "VULNERABLE",
        "description": "Insecure random number for security-sensitive value",
    },
    {
        "code": "int sessionToken = new SecureRandom().nextInt();",
        "expected": "NOT_VULNERABLE",
        "description": "Cryptographically secure random number",
    },
]
