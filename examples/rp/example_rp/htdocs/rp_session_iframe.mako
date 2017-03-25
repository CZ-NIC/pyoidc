<!DOCTYPE html>
<html>
<head lang="en">
    <meta charset="UTF-8">
    <title></title>
</head>
<body>

<script type="application/javascript">
    var client_id = "${client_id}";
    var session_state = "${session_state}";
    console.log("RP session state: " + session_state);
    var targetOrigin = "${issuer}".replace(/\/$/, "");

    var stat = "unchanged";
    var mes = client_id + " " + session_state;

    window.addEventListener("message", receiveMessage, false);
    checkSession();
    console.log("RP iframe, starting timer.");
    var timer_id = setInterval(checkSession, 5 * 1000);

    function checkSession() {
        var win = window.parent.document.getElementById("op_iframe").contentWindow;
        win.postMessage(mes, targetOrigin);
    }

    function receiveMessage(e) {
        console.log("origin: " + e.origin + " expected: " + targetOrigin);
        if (e.origin !== targetOrigin) {
            return;
        }
        stat = e.data;

        if (stat == "changed") {
            clearInterval(timer_id);
            alert("Your session has changed, you will be redirected to log in again.");
            window.parent.window.location = "${session_change_url}";
        }
    }
</script>

</body>
</html>