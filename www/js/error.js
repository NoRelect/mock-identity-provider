let message = document.getElementById("message");
if (message) {
    let params = new URLSearchParams(window.location.search);
    message.innerText = params.get("message") || "No detailed error message provided.";
}