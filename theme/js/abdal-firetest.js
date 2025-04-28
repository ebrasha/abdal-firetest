/**
 Create a panel, and add listeners for panel show/hide events.
 */
try {
    browser.devtools.panels.create(
        "Abdal FireTest",
        "/icons/icon.png",
        "/theme/abdal-firetest-panel.html"
    );
} catch (e) {
}
