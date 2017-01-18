<!DOCTYPE html>

<html>
<head>
    <title>OpenID Certification OP Test</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="static/opresultqr.css" rel="stylesheet" media="screen">

    <!-- Bootstrap -->
    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">

    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
    <script src="../../assets/js/html5shiv.js"></script>
    <script src="../../assets/js/respond.min.js"></script>
    <![endif]-->

    <script src="/static/jquery.min.1.9.1.js"></script>
    <script src="/static/parse_URI_fragment.js"></script>
</head>
<body onload="document.forms[0].submit()">
<div class="container">
    <div class="jumbotron">
        <form class="repost" action="/authz_post" method="post">
            <input type="hidden" name="fragment" id="frag" value="x"/>
            <script type="text/javascript">
                if(window.location.hash) {
                    var hash = window.location.hash.substring(1); //Puts hash in variable, and removes the # character
                    document.getElementById("frag").value = hash;
                }
            </script>
        </form>
    </div>
</div>
</body>
</html>
