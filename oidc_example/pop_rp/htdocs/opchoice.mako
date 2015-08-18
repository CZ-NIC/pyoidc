<%!
    def op_choice(op_list):
        #Creates a dropdown list of OpenID Connect providers
        element = "<select name=\"op\">"
        for name in op_list:
            element += "<option value=\"%s\">%s</option>" % (name, name)
        element += "</select>"
        return element
%>

<!DOCTYPE html>

<html>
<head>
    <title>pyoidc RP</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
    <link href="static/style.css" rel="stylesheet" media="all">

    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
    <script src="../../assets/js/html5shiv.js"></script>
    <script src="../../assets/js/respond.min.js"></script>
    <![endif]-->
</head>
<body>

<!-- Static navbar -->
<div class="navbar navbar-default navbar-fixed-top">
    <div class="navbar-header">
        <a class="navbar-brand" href="#">pyoidc RP</a>
    </div>
</div>

<div class="container">
    <!-- Main component for a primary marketing message or call to action -->
    <div class="jumbotron">
        <form class="form-signin" action="rp" method="get">
            <h1>OP by UID</h1>

            <h3>Chose the OpenID Connect Provider: </h3>

            <p>From this list</p>
            ${op_choice(op_list)}
            <p> OR by providing your unique identifier at the OP. </p>
            <input type="text" id="uid" name="uid" class="form-control" placeholder="UID" autofocus>
            <button class="btn btn-lg btn-primary btn-block" type="submit">Start</button>
        </form>
    </div>

</div>
<!-- /container -->
<!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
<script src="/static/jquery.min.1.9.1.js"></script>
<!-- Include all compiled plugins (below), or include individual files as needed -->
<script src="/static/bootstrap/js/bootstrap.min.js"></script>

</body>
</html>