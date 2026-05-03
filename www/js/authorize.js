function error(message) {
    let errorParams = new URLSearchParams();
    errorParams.append("message", message);
    window.location.assign("/error.html?" + errorParams.toString());
}

async function authorize(user, client, redirectUri, scope, responseType, responseMode, state, nonce) {
    let formData = new URLSearchParams();
    formData.append("grant_type", "password");
    formData.append("username", user);
    formData.append("client_id", client);
    formData.append("scope", scope);
    formData.append("nonce", nonce);

    // Use password flow to get user tokens
    let tokenResponse = await fetch("token", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: formData.toString()
    })
    let tokens = await tokenResponse.json();
    let accessToken = tokens.access_token;
    let idToken = tokens.id_token;

    let returnUrl = new URL(redirectUri);
    let query = new URLSearchParams();
    if (state) {
        query.append("state", state);
    }

    if (responseType == "code") {
        let code = btoa(JSON.stringify({
            "sub": user,
            "scp": scope,
            "aud": client,
            "nonce": nonce,
            "iat": new Date().toISOString()
        }));
        query.append("code", code);
    } else if (responseType == "token") {
        query.append("access_token", accessToken);
    } else if (responseType == "id_token token") {
        query.append("access_token", accessToken);
        query.append("id_token", idToken);
    } else {
        return error("response_type not implemented: " + responseType);
    }

    if (responseMode == "query") {
        returnUrl.search = "?" + query.toString();
        window.location.assign(returnUrl);
    } else if (responseMode == "fragment") {
        returnUrl.hash = "#" + query.toString();
        window.location.assign(returnUrl);
    } else if (responseMode == "form_post") {
        let form = document.createElement('form');
        form.method = "POST";
        form.action = returnUrl.toString();
        query.forEach((value, key) => {
            let hiddenField = document.createElement("input");
            hiddenField.type = "hidden";
            hiddenField.name = key;
            hiddenField.value = value;
            form.appendChild(hiddenField);
        });
        document.body.appendChild(form);
        form.submit();
    } else {
        return error("response_mode not implemented: " + responseMode);
    }
}

async function initialize() {
    let params = new URLSearchParams(window.location.search);
    let clientId = params.get("client_id");
    if (!clientId) {
        return error("client_id is required, but missing");
    }

    let responseType = params.get("response_type");
    if (!responseType) {
        return error("response_type is required, but missing");
    }

    let redirectUri = params.get("redirect_uri");
    if (!redirectUri) {
        return error("redirect_uri is required");
    }

    let parsedUrl = URL.parse(redirectUri);
    if (parsedUrl == null || parsedUrl.hostname == "" || !["http:", "https:"].includes(parsedUrl.protocol)) {
        return error("redirect_uri has to be a valid absolute URL that starts with http:// or https://");
    }

    if (parsedUrl.search != "") {
        return error("redirect_uri can't contain query parameters");
    }

    if (!OPENID_CONFIG.response_types_supported.includes(responseType)) {
        return error("Unsupported response type: " + responseType);
    }

    let responseMode = params.get("response_mode");
    if (!responseMode) {
        // Handle default response mode fallback
        if (responseType == "code") {
            responseMode = "query";
        } else if (responseType == "id_token token") {
            responseMode = "fragment";
        } else if (responseType == "token") {
            responseMode = "fragment";
        } else {
            return error("Unable to determine default response_mode for response_type: " + responseType);
        }
    }

    let response_modes_supported = ["query", "fragment", "form_post"];
    if (!response_modes_supported.includes(responseMode)) {
        return error("Unsupported response mode: " + responseMode);
    }

    let state = params.get("state");
    let scope = params.get("scope");
    let nonce = params.get("nonce");

    // Replace all placeholders with the actual issuer URL
    let issuers = document.getElementsByClassName("replace-issuer");
    for (let i = 0; i < issuers.length; i++) {
        issuers[i].innerText = issuers[i].innerText.replace("ISSUER_PLACEHOLDER", APP_CONFIG.issuer);
    }

    let users = document.getElementById("users");
    if (users) {
        APP_CONFIG.users.forEach(user => {
            let article = document.createElement("article");
            article.onclick = async () => await authorize(user.sub, clientId, redirectUri, scope, responseType, responseMode, state, nonce);
            let title = document.createElement("h3");
            if (user.claims.name) {
                title.innerText = user.claims.name;
            } else {
                title.innerText = user.sub;
            }
            article.appendChild(title);
            let claims = document.createElement("pre");
            user.claims.sub = user.sub;
            claims.innerText = JSON.stringify(user.claims, null, 4);
            article.appendChild(claims);
            users.appendChild(article);
        });
    }

    document.getElementById("error").onclick = () => {
        let returnUrl = new URL(redirectUri);
        let query = new URLSearchParams();
        query.append("error", "some_error");
        query.append("error_description", "Some simulated error has happened");
        query.append("error_uri", APP_CONFIG.issuer + "docs/errors#some_error");

        if (state) {
            query.append("state", state);
        }

        if (responseMode == "query") {
            returnUrl.search = "?" + query.toString();
            window.location.assign(returnUrl);
        } else if (responseMode == "fragment") {
            returnUrl.hash = "#" + query.toString();
            window.location.assign(returnUrl);
        } else if (responseMode == "form_post") {
            let form = document.createElement('form');
            form.method = "POST";
            form.action = returnUrl.toString();
            query.forEach((value, key) => {
                let hiddenField = document.createElement("input");
                hiddenField.type = "hidden";
                hiddenField.name = key;
                hiddenField.value = value;
                form.appendChild(hiddenField);
            });
            document.body.appendChild(form);
            form.submit();
        } else {
            return error("response_mode not implemented: " + responseMode);
        }
    };
}

initialize();