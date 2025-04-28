/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal FireTest
 * File Name    : wp-security-tools.js
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2023-08-02 14:30:00
 * Description  : WordPress Security Testing Tools for Abdal FireTest
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

// WordPress Config Leak Check
function wpConfigLeakCheck() {
    // Get URL from the input field
    let url = $('#url_field').val();
    if (!url) {
        // If URL field is empty, try to load it from the current tab
        loadUrl();
        return;
    }

    // Normalize URL
    url = normalizeUrl(url);
    if (!url) {
        showResultMessage('Invalid URL format', 'danger');
        return;
    }

    // Clear previous results
    clearResults();
    
    // Show loading indicator
    showLoading('Checking for WordPress configuration file leaks...');

    // Create result container
    let resultContainer = $('<div class="wp-check-results cyberpunk-border" style="background-color: #121212;"></div>');
    $('#url_field').after(resultContainer);

    // Paths to check
    const configPaths = [
        '/wp-config.php',
        '/wp-config.php.bak',
        '/wp-config.php.old',
        '/wp-config.php.save',
        '/wp-config.php.swp',
        '/wp-config.php.swo',
        '/wp-config.php~',
        '/wp-config.php.orig',
        '/wp-config.txt',
        '/wp-config.php.txt',
        '/wp-config-sample.php'
    ];

    let resultTable = $('<table class="table table-bordered cyberpunk-table" style="background-color: #121212;">' +
        '<thead style="background-color: #1a1a2e;"><tr>' +
        '<th style="background-color: #1a1a2e; color: var(--neon-blue);">Path</th>' +
        '<th style="background-color: #1a1a2e; color: var(--neon-blue);">Status</th>' +
        '<th style="background-color: #1a1a2e; color: var(--neon-blue);">Details</th>' +
        '</tr></thead>' +
        '<tbody style="background-color: #1e1e2f;"></tbody>' +
        '</table>');

    resultContainer.append('<h3 class="neon-text" style="color: var(--neon-green);">WP Config Leak Check Results</h3>');
    resultContainer.append('<p>Target: <span class="neon-text" style="color: var(--neon-blue);">' + url + '</span></p>');
    resultContainer.append(resultTable);

    let completedChecks = 0;
    
    // Check each path
    configPaths.forEach(path => {
        const fullUrl = url + path;
        
        // Make HTTP request to check the path
        fetch(fullUrl, { method: 'HEAD', mode: 'no-cors' })
            .then(response => {
                let status = 'Safe';
                let details = 'File not accessible (404/403)';
                let rowClass = 'success';
                let bgColor = 'rgba(0, 40, 0, 0.8)';
                
                // Check response status
                if (response.ok) {
                    status = 'VULNERABLE';
                    details = 'File is publicly accessible!';
                    rowClass = 'danger';
                    bgColor = 'rgba(40, 0, 40, 0.8)';
                }
                
                // Add result to table
                addResultRow(path, status, details, rowClass, bgColor);
                completedChecks++;
                
                // If all checks are completed, hide loading indicator
                if (completedChecks === configPaths.length) {
                    hideLoading();
                }
            })
            .catch(error => {
                // Add error result to table
                addResultRow(path, 'Error', 'Error checking this path', 'warning', 'rgba(40, 40, 0, 0.8)');
                completedChecks++;
                
                // If all checks are completed, hide loading indicator
                if (completedChecks === configPaths.length) {
                    hideLoading();
                }
            });
    });
    
    // Helper function to add row to result table
    function addResultRow(path, status, details, rowClass, bgColor) {
        const row = $('<tr class="' + rowClass + '" style="background-color: ' + bgColor + ';">' +
            '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + path + '</td>' +
            '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + status + '</td>' +
            '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + details + '</td>' +
            '</tr>');
        resultTable.find('tbody').append(row);
    }
}

// WordPress Version Detection
function wpVersionDetect() {
    // Get URL from the input field
    let url = $('#url_field').val();
    if (!url) {
        // If URL field is empty, try to load it from the current tab
        loadUrl();
        return;
    }

    // Normalize URL
    url = normalizeUrl(url);
    if (!url) {
        showResultMessage('Invalid URL format', 'danger');
        return;
    }

    // Clear previous results
    clearResults();
    
    // Show loading indicator
    showLoading('Detecting WordPress version...');

    // Create result container
    let resultContainer = $('<div class="wp-version-results cyberpunk-border" style="background-color: #121212;"></div>');
    $('#url_field').after(resultContainer);
    
    resultContainer.append('<h3 class="neon-text" style="color: var(--neon-green);">WordPress Version Detection Results</h3>');
    resultContainer.append('<p style="color: #e0e0e0;">Target: <span class="neon-text" style="color: var(--neon-blue);">' + url + '</span></p>');

    // Fetch the homepage
    fetch(url)
        .then(response => response.text())
        .then(html => {
            // Try to detect WordPress version
            let version = detectWordPressVersion(html);
            let versionInfo = '';
            
            if (version) {
                versionInfo = '<span class="neon-text" style="color: var(--neon-pink);">' + version + '</span>';
                checkWordPressVulnerabilities(version, resultContainer);
            } else {
                versionInfo = '<span class="neon-text" style="color: var(--neon-yellow);">Could not detect WordPress version</span>';
                resultContainer.append('<div class="detection-method" style="background-color: #1a1a2e; color: #e0e0e0;">' +
                    '<h4 style="color: var(--neon-blue);">Detection Methods</h4>' +
                    '<ul>' +
                    '<li>Meta Generator Tag: Not found</li>' +
                    '<li>CSS/JS Version Strings: Not found</li>' +
                    '<li>Feed Links: Not found</li>' +
                    '</ul>' +
                    '</div>');
            }
            
            resultContainer.prepend('<div class="version-info" style="background-color: #1a1a2e; color: #e0e0e0;">' +
                '<h4 style="color: var(--neon-blue);">Detected Version</h4>' +
                '<p>' + versionInfo + '</p>' +
                '</div>');
            
            hideLoading();
        })
        .catch(error => {
            resultContainer.append('<div class="error-message" style="background-color: #1a1a2e; color: #e0e0e0;">' +
                '<p>Error fetching the website: ' + error.message + '</p>' +
                '</div>');
            hideLoading();
        });
}

// Helper function to detect WordPress version from HTML
function detectWordPressVersion(html) {
    let version = null;
    let detectionMethod = '';
    let detectionDetails = [];
    
    // Try to detect from meta generator tag
    const metaMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s*([0-9.]+)["'][^>]*>/i);
    if (metaMatch && metaMatch[1]) {
        version = metaMatch[1];
        detectionMethod = 'Meta Generator Tag';
        detectionDetails.push('Found via Meta Generator Tag: ' + metaMatch[0]);
    }
    
    // If not found, try to detect from CSS/JS version strings
    if (!version) {
        const cssJsMatch = html.match(/\/wp-(content|includes)\/.+[?&]ver=([0-9.]+)/i);
        if (cssJsMatch && cssJsMatch[2]) {
            version = cssJsMatch[2];
            detectionMethod = 'CSS/JS Version Strings';
            detectionDetails.push('Found via CSS/JS Version String: ' + cssJsMatch[0]);
        }
    }
    
    // If not found, try to detect from feed links
    if (!version) {
        const feedMatch = html.match(/\/\?feed=(rss|rdf|atom)&amp;ver=([0-9.]+)/i);
        if (feedMatch && feedMatch[2]) {
            version = feedMatch[2];
            detectionMethod = 'Feed Links';
            detectionDetails.push('Found via Feed Link: ' + feedMatch[0]);
        }
    }
    
    // Display detection methods if version was found
    if (version) {
        const detectionMethodsDiv = $('<div class="detection-method" style="background-color: #1a1a2e; color: #e0e0e0;">' +
            '<h4 style="color: var(--neon-blue);">Detection Methods</h4>' +
            '<ul></ul>' +
            '</div>');
        
        detectionDetails.forEach(detail => {
            detectionMethodsDiv.find('ul').append('<li>' + detail + '</li>');
        });
        
        $('.wp-version-results').append(detectionMethodsDiv);
    }
    
    return version;
}

// Check for known vulnerabilities for a WordPress version
function checkWordPressVulnerabilities(version, container) {
    // This is a simplified vulnerability check
    // In a real-world scenario, you'd connect to a vulnerability database API
    
    let vulnerabilitiesDiv = $('<div class="vulnerabilities" style="background-color: #1a1a2e; color: #e0e0e0;">' +
        '<h4 style="color: var(--neon-blue);">Known Vulnerabilities</h4>' +
        '<div class="loading">Checking for known vulnerabilities...</div>' +
        '</div>');
    
    container.append(vulnerabilitiesDiv);
    
    // Simulate vulnerability check (would be replaced with actual API call)
    setTimeout(() => {
        let vulnerabilities = [];
        
        // Simple version check for demonstration
        const versionNum = parseFloat(version);
        
        if (versionNum < 5.8) {
            vulnerabilities.push({
                title: 'Object Injection Vulnerability in PHPMailer',
                severity: 'High',
                description: 'Affected versions contain an object injection vulnerability in PHPMailer that could lead to remote code execution.',
                cve: 'CVE-2020-36326'
            });
        }
        
        if (versionNum < 5.7) {
            vulnerabilities.push({
                title: 'SQL Injection in WP_Query',
                severity: 'Critical',
                description: 'SQL injection vulnerability affecting the WP_Query class.',
                cve: 'CVE-2022-21661'
            });
        }
        
        if (versionNum < 5.5) {
            vulnerabilities.push({
                title: 'Cross-Site Scripting (XSS) in Media Library',
                severity: 'Medium',
                description: 'XSS vulnerability in the media library component.',
                cve: 'CVE-2021-29450'
            });
        }
        
        // Display vulnerabilities
        vulnerabilitiesDiv.find('.loading').remove();
        
        if (vulnerabilities.length > 0) {
            let vulnTable = $('<table class="table table-bordered cyberpunk-table" style="background-color: #121212;">' +
                '<thead style="background-color: #1a1a2e;"><tr>' +
                '<th style="background-color: #1a1a2e; color: var(--neon-blue);">Title</th>' +
                '<th style="background-color: #1a1a2e; color: var(--neon-blue);">Severity</th>' +
                '<th style="background-color: #1a1a2e; color: var(--neon-blue);">CVE</th>' +
                '<th style="background-color: #1a1a2e; color: var(--neon-blue);">Description</th>' +
                '</tr></thead>' +
                '<tbody style="background-color: #1e1e2f;"></tbody>' +
                '</table>');
            
            vulnerabilities.forEach(vuln => {
                let severityClass = '';
                let bgColor = '';
                switch (vuln.severity.toLowerCase()) {
                    case 'critical':
                        severityClass = 'danger';
                        bgColor = 'rgba(40, 0, 40, 0.8)';
                        break;
                    case 'high':
                        severityClass = 'warning';
                        bgColor = 'rgba(40, 40, 0, 0.8)';
                        break;
                    case 'medium':
                        severityClass = 'info';
                        bgColor = 'rgba(0, 0, 40, 0.8)';
                        break;
                    default:
                        severityClass = 'success';
                        bgColor = 'rgba(0, 40, 0, 0.8)';
                }
                
                vulnTable.find('tbody').append('<tr class="' + severityClass + '" style="background-color: ' + bgColor + ';">' +
                    '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + vuln.title + '</td>' +
                    '<td style="background-color: ' + bgColor + '; color: #e0e0e0;"><span class="label label-' + severityClass + '">' + vuln.severity + '</span></td>' +
                    '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + vuln.cve + '</td>' +
                    '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + vuln.description + '</td>' +
                    '</tr>');
            });
            
            vulnerabilitiesDiv.append(vulnTable);
        } else {
            vulnerabilitiesDiv.append('<p style="color: #e0e0e0;">No known vulnerabilities found for WordPress ' + version + '</p>');
        }
    }, 1500);
}

// WordPress Directory Listing Detection
function wpDirectoryListingDetection() {
    // Get URL from the input field
    let url = $('#url_field').val();
    if (!url) {
        // If URL field is empty, try to load it from the current tab
        loadUrl();
        return;
    }

    // Normalize URL
    url = normalizeUrl(url);
    if (!url) {
        showResultMessage('Invalid URL format', 'danger');
        return;
    }

    // Clear previous results
    clearResults();
    
    // Show loading indicator
    showLoading('Checking for WordPress directory listing vulnerabilities...');

    // Create result container
    let resultContainer = $('<div class="wp-check-results cyberpunk-border" style="background-color: #121212;"></div>');
    $('#url_field').after(resultContainer);

    // Directories to check
    const directories = [
        '/wp-content/',
        '/wp-content/plugins/',
        '/wp-content/uploads/',
        '/wp-content/themes/',
        '/wp-includes/',
        '/wp-admin/css/',
        '/wp-admin/js/',
        '/wp-admin/images/'
    ];

    let resultTable = $('<table class="table table-bordered cyberpunk-table" style="background-color: #121212;">' +
        '<thead style="background-color: #1a1a2e;"><tr>' +
        '<th style="background-color: #1a1a2e; color: var(--neon-blue);">Directory</th>' +
        '<th style="background-color: #1a1a2e; color: var(--neon-blue);">Status</th>' +
        '<th style="background-color: #1a1a2e; color: var(--neon-blue);">Details</th>' +
        '</tr></thead>' +
        '<tbody style="background-color: #1e1e2f;"></tbody>' +
        '</table>');

    resultContainer.append('<h3 class="neon-text" style="color: var(--neon-green);">Directory Listing Detection Results</h3>');
    resultContainer.append('<p>Target: <span class="neon-text" style="color: var(--neon-blue);">' + url + '</span></p>');
    resultContainer.append('<p style="color: #e0e0e0;">Checking if directory listing is enabled for sensitive WordPress directories...</p>');
    resultContainer.append(resultTable);

    let completedChecks = 0;
    
    // Check each directory
    directories.forEach(dir => {
        const fullUrl = url + dir;
        
        // Make HTTP request to check the path
        fetch(fullUrl)
            .then(response => response.text())
            .then(html => {
                let status = 'Safe';
                let details = 'Directory listing disabled';
                let rowClass = 'success';
                let bgColor = 'rgba(0, 40, 0, 0.8)';
                
                // Check if directory listing is enabled by looking for typical markers
                if (html.includes('<title>Index of') || 
                    html.includes('Directory Listing For') || 
                    html.includes('Directory listing for')) {
                    status = 'VULNERABLE';
                    details = 'Directory listing is enabled!';
                    rowClass = 'danger';
                    bgColor = 'rgba(40, 0, 40, 0.8)';
                }
                
                // Add result to table
                addResultRow(dir, status, details, rowClass, bgColor);
                completedChecks++;
                
                // If all checks are completed, hide loading indicator
                if (completedChecks === directories.length) {
                    hideLoading();
                    addSecurityRecommendations(resultContainer);
                }
            })
            .catch(error => {
                // Add error result to table
                addResultRow(dir, 'Unknown', 'Error checking this directory', 'warning', 'rgba(40, 40, 0, 0.8)');
                completedChecks++;
                
                // If all checks are completed, hide loading indicator
                if (completedChecks === directories.length) {
                    hideLoading();
                    addSecurityRecommendations(resultContainer);
                }
            });
    });
    
    // Helper function to add row to result table
    function addResultRow(dir, status, details, rowClass, bgColor) {
        const row = $('<tr class="' + rowClass + '" style="background-color: ' + bgColor + ';">' +
            '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + dir + '</td>' +
            '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + status + '</td>' +
            '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + details + '</td>' +
            '</tr>');
        resultTable.find('tbody').append(row);
    }
    
    // Add security recommendations
    function addSecurityRecommendations(container) {
        let recommendationsDiv = $('<div class="security-recommendations" style="background-color: #1a1a2e; color: #e0e0e0;">' +
            '<h4 class="neon-text" style="color: var(--neon-blue);">Security Recommendations</h4>' +
            '<ul class="recommendations-list cyberpunk-list">' +
            '<li>Add <code style="background-color: #2a2a40; color: var(--neon-green);">Options -Indexes</code> to your .htaccess file to disable directory listing on Apache servers</li>' +
            '<li>For Nginx, add <code style="background-color: #2a2a40; color: var(--neon-green);">autoindex off;</code> in your server configuration</li>' +
            '<li>Use a security plugin like Wordfence, Sucuri, or iThemes Security to enforce proper security measures</li>' +
            '<li>Implement proper file permissions: 755 for directories and 644 for files</li>' +
            '<li>Regularly update WordPress core, themes, and plugins to patch security vulnerabilities</li>' +
            '</ul>' +
            '</div>');
        
        container.append(recommendationsDiv);
    }
}

// Helper function to normalize URL
function normalizeUrl(url) {
    url = url.trim();
    
    // Remove newlines and carriage returns
    url = url.replace(/\n|\r/g, '');
    
    // Add protocol if missing
    if (!url.match(/^(http:\/\/|https:\/\/)/i)) {
        url = 'http://' + url;
    }
    
    // Remove trailing slash if present
    if (url.endsWith('/')) {
        url = url.slice(0, -1);
    }
    
    try {
        new URL(url);
        return url;
    } catch (e) {
        return null;
    }
}

// Helper function to show loading indicator
function showLoading(message) {
    if ($('.loading-indicator').length === 0) {
        const loadingIndicator = $('<div class="loading-indicator cyberpunk-border" style="background-color: #121212; border: 2px solid var(--neon-blue); border-radius: 5px;">' +
            '<div class="spinner"></div>' +
            '<div class="message" style="color: var(--neon-blue);">' + message + '</div>' +
            '</div>');
        $('#url_field').after(loadingIndicator);
    } else {
        $('.loading-indicator .message').text(message);
        $('.loading-indicator').show();
    }
}

// Helper function to hide loading indicator
function hideLoading() {
    $('.loading-indicator').hide();
}

// Helper function to clear previous results
function clearResults() {
    $('.wp-check-results, .wp-version-results').remove();
}

// Helper function to show result message
function showResultMessage(message, type) {
    const alertClass = 'alert-' + (type || 'info');
    let bgColor = '#121212';
    let color = '#e0e0e0';
    
    switch(type) {
        case 'danger':
            bgColor = 'rgba(40, 0, 0, 0.8)';
            color = 'var(--neon-pink)';
            break;
        case 'warning':
            bgColor = 'rgba(40, 20, 0, 0.8)';
            color = 'var(--neon-yellow)';
            break;
        case 'success':
            bgColor = 'rgba(0, 40, 0, 0.8)';
            color = 'var(--neon-green)';
            break;
        case 'info':
        default:
            bgColor = 'rgba(0, 0, 40, 0.8)';
            color = 'var(--neon-blue)';
            break;
    }
    
    const alertDiv = $('<div class="alert ' + alertClass + '" style="background-color: ' + bgColor + '; color: ' + color + '; border: 1px solid ' + color + ';">' + message + '</div>');
    $('#url_field').after(alertDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        alertDiv.fadeOut(500, () => alertDiv.remove());
    }, 5000);
}

// Add CSS styles for the tools
function addWpToolsStyles() {
    const styleElement = document.createElement('style');
    styleElement.textContent = `
        .cyberpunk-table {
            background-color: #121212 !important;
            color: #e0e0e0 !important;
            border: 2px solid var(--cyberpunk-blue) !important;
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }
        
        .cyberpunk-table thead th {
            background-color: #1a1a2e !important;
            border-bottom: 2px solid var(--neon-blue) !important;
            color: var(--neon-blue) !important;
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 1px;
            padding: 12px 15px;
        }
        
        .cyberpunk-table tbody td,
        .cyberpunk-table td {
            border: 1px solid rgba(10, 189, 198, 0.3) !important;
            padding: 10px 15px;
            background-color: #1e1e2f !important;
            color: #e0e0e0 !important;
        }
        
        .cyberpunk-table tr.danger td {
            color: var(--neon-pink) !important;
            border-color: rgba(234, 0, 217, 0.3) !important;
            background-color: rgba(40, 0, 40, 0.8) !important;
        }
        
        .cyberpunk-table tr.success td {
            color: var(--neon-green) !important;
            background-color: rgba(0, 40, 0, 0.8) !important;
        }
        
        .cyberpunk-table tr.warning td {
            color: var(--neon-yellow) !important;
            background-color: rgba(40, 40, 0, 0.8) !important;
        }
        
        /* Add direct targeting for table elements */
        table.cyberpunk-table > tbody > tr > td {
            background-color: #1e1e2f !important;
            color: #e0e0e0 !important;
        }
        
        table.cyberpunk-table > tbody > tr.danger > td {
            background-color: rgba(40, 0, 40, 0.8) !important;
        }
        
        table.cyberpunk-table > tbody > tr.success > td {
            background-color: rgba(0, 40, 0, 0.8) !important;
        }
        
        table.cyberpunk-table > tbody > tr.warning > td {
            background-color: rgba(40, 40, 0, 0.8) !important;
        }
        
        .loading-indicator {
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            padding: 20px;
            margin: 15px 0;
            background-color: #121212;
            border: 2px solid var(--neon-blue);
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(10, 189, 198, 0.5);
        }
        
        .loading-indicator .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid rgba(10, 189, 198, 0.3);
            border-top: 4px solid var(--neon-blue);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 15px;
        }
        
        .loading-indicator .message {
            color: var(--neon-blue);
            font-family: 'Rajdhani', sans-serif;
            letter-spacing: 1px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .wp-check-results, .wp-version-results {
            margin: 15px 0;
            padding: 15px;
            background-color: #121212;
            border: 2px solid var(--neon-blue);
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(10, 189, 198, 0.5);
        }
        
        .detection-method, .version-info, .vulnerabilities {
            margin: 15px 0;
            padding: 15px;
            background-color: #1a1a2e;
            border-left: 3px solid var(--neon-green);
        }
        
        .detection-method h4, .version-info h4, .vulnerabilities h4 {
            color: var(--neon-blue);
            margin-top: 0;
            margin-bottom: 10px;
            font-family: 'Orbitron', sans-serif;
            letter-spacing: 1px;
        }
        
        .security-recommendations {
            margin: 15px 0;
            padding: 15px;
            background-color: #1a1a2e;
            border-left: 3px solid var(--neon-blue);
        }
        
        .recommendations-list li {
            margin-bottom: 10px;
            color: #e0e0e0;
        }
        
        .recommendations-list code {
            background-color: #2a2a40;
            color: var(--neon-green);
            padding: 2px 5px;
            border-radius: 3px;
        }
        
        .label {
            padding: 3px 6px;
            border-radius: 3px;
            font-size: 12px;
            text-transform: uppercase;
            font-weight: bold;
        }
        
        .label-danger {
            background-color: rgba(234, 0, 217, 0.2);
            color: var(--neon-pink);
            border: 1px solid var(--neon-pink);
        }
        
        .label-warning {
            background-color: rgba(255, 238, 0, 0.2);
            color: var(--neon-yellow);
            border: 1px solid var(--neon-yellow);
        }
        
        .label-info {
            background-color: rgba(10, 189, 198, 0.2);
            color: var(--neon-blue);
            border: 1px solid var(--neon-blue);
        }
        
        .label-success {
            background-color: rgba(57, 255, 20, 0.2);
            color: var(--neon-green);
            border: 1px solid var(--neon-green);
        }
    `;
    document.head.appendChild(styleElement);
}

// Initialize the tools
$(document).ready(function() {
    // Add CSS styles for the tools
    addWpToolsStyles();
}); 