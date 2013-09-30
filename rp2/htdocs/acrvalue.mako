<!DOCTYPE html>

<%!
    import htmlentitydefs
    import re, string

    def createResult(acrvalues):
      """
      Creates a dropdown based on the service configurtion.
      """
      element = ""
      for acr in acrvalues:
        name = acr
        if acr == "PASSWORD":
            name = "Username password authentication"
        elif acr == "CAS":
            name = "CAS authentication"
        elif acr == "SAML":
            name = "SAML IdP authentication"
        element += "<div class='col-md-12'>"
        element += "<a href='rpAuth?acr=" + acr + "'>"
        element += name
        element += "</a>"
        element += "</div>"
      return element
%>

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
            <li><a href="opbyuid">OP by unique id</a></li>
          </ul>
        </div><!--/.nav-collapse -->
    </div>

    <div class="container">
     <!-- Main component for a primary marketing message or call to action -->
      <div class="jumbotron">
        <h2>Choose authentication method to use: </h2>
        ${createResult(acrvalues)}
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>


  </body>
</html>