function error(message) {
    let errorParams = new URLSearchParams();
    errorParams.append("message", message);
    window.location.assign("/error.html?" + errorParams.toString());
}

function initialize() {
    let fragment = window.location.hash;
    if (fragment == "") {
        return error("No token information supplied in URL fragment");
    }

    let params = new URLSearchParams(fragment.substring(1));

    let error_type = params.get("error");
    let error_description = params.get("error_description") || "No further details provided";
    if (error_type) {
        return error("Error during authentication: " + error_type + " (" + error_description + ")");
    }

    let accessToken = params.get("access_token");
    if (!accessToken) {
        return error("access_token is required, but missing");
    }

    let idToken = params.get("id_token");

    document.getElementById("accessToken").innerText = accessToken;
    document.getElementById("idToken").innerText = idToken;

    let decodedAccessToken = JSON.stringify(JSON.parse(atob(accessToken.split('.')[1])), null, 4);
    document.getElementById("decodedAccessToken").innerText = decodedAccessToken;

    let decodedIdToken = JSON.stringify(JSON.parse(atob(idToken.split('.')[1])), null, 4);
    document.getElementById("decodedIdToken").innerText = decodedIdToken;

    // Replace all placeholders with the actual issuer URL
    let issuers = document.getElementsByClassName("replace-issuer");
    for (let i = 0; i < issuers.length; i++) {
        issuers[i].innerText = issuers[i].innerText.replace("ISSUER_PLACEHOLDER", APP_CONFIG.issuer);
    }
}

initialize();