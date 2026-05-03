async function initialize() {
    // If the demo authentication button exists on the page, register a click handler
    let triggerDemoAuth = document.getElementById("triggerDemoAuth");
    if (triggerDemoAuth) {
        triggerDemoAuth.onclick = function () {
            let issuer = window.location.protocol + "//" + window.location.host;
            let paramsObj = {
                "client_id": "demo",
                "response_type": "id_token token",
                "scope": "openid",
                "state": "state_value",
                "nonce": "nonce_value",
                "redirect_uri": issuer + "/inspect.html"
            };
            let searchParams = new URLSearchParams(paramsObj);
            window.location.assign("/authorize.html?" + searchParams.toString());
        };
    }

    // Replace all placeholders with the actual issuer URL
    let issuers = document.getElementsByClassName("replace-issuer");
    for (let i = 0; i < issuers.length; i++) {
        issuers[i].innerText = issuers[i].innerText.replace("ISSUER_PLACEHOLDER", APP_CONFIG.issuer);
    }
}

initialize();