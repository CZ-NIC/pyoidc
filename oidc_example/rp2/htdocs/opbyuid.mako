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
          <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="navbar-brand" href="#">pyoidc RP</a>
        </div>
        <div class="navbar-collapse collapse">
          <ul class="nav navbar-nav">
            <li><a href="/">Home</a></li>
            <li class="active"><a href="opbyuid">OP by unique id</a></li>
          </ul>
        </div><!--/.nav-collapse -->
    </div>

    <div class="container">
     <!-- Main component for a primary marketing message or call to action -->
      <div class="jumbotron">
        <h1>OP by UID</h1>
        <p>
            You can perform a login to an OP's by using your unique identifier at the OP.
            A unique identifier is defined as your username@opserver, this may be equal to an e-mail address.
            A unique identifier is only equal to an e-mail address if the op server is published at the same
            server address as your e-mail provider.
        </p>
        <form class="form-signin" action="rp" method="get">
            <h2 class="form-signin-heading">Start sign in flow</h2>
            <input type="text" id="uid" name="uid" class="form-control" placeholder="UID" autofocus>
            <button class="btn btn-lg btn-primary btn-block" type="submit">Start</button>
        </form>
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>


  </body>
</html>