function error(message) {
    let errorParams = new URLSearchParams();
    errorParams.append("message", message);
    window.location.assign("/error.html?" + errorParams.toString());
}

async function initialize() {
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

    let userInfoResponse = await fetch("userinfo", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Bearer " + accessToken,
        }
    })
    let userInfo = await userInfoResponse.json();
    document.getElementById("user-info").innerText = JSON.stringify(userInfo, null, 4);;

    // Replace all placeholders with the actual issuer URL
    let issuers = document.getElementsByClassName("replace-issuer");
    for (let i = 0; i < issuers.length; i++) {
        issuers[i].innerText = issuers[i].innerText.replace("ISSUER_PLACEHOLDER", APP_CONFIG.issuer);
    }
}

initialize();