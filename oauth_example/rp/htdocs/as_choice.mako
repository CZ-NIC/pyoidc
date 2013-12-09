<%!
def as_choice(as_list):
    """
    Creates a dropdown list of authorization servers
    """
    element = "<select name=\"authzsrv\">"
    for name in as_list:
        element += "<option value=\"%s\">%s</option>" % (name, name)
    element += "</select>"
    return element
%>

<html>
  <head>
    <title>OAuth2 RP Example</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Bootstrap -->
    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">
    <link href="static/style.css" rel="stylesheet" media="all">

    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
    <script src="../../assets/js/html5shiv.js"></script>
    <script src="../../assets/js/respond.min.js"></script>
    <style type="text/css">
      tbody tr:nth-child(odd){ background-color:#ccc; }
    </style>
    <![endif]-->
  </head>
  <body>

    <div class="container">
     <!-- Main component for a primary marketing message or call to action -->
      <div class="jumbotron">
        <form action="${action}" method="${method}">
            <h3>Choose the Authorization Server: </h3>
            ${as_choice(as_list)}
            <hr>
            <br>
            <input type="submit" name="commit" value="select"/>
        </form>
      </div>

    </div> <!-- /container -->
    <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
    <script src="/static/jquery.min.1.9.1.js"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script src="/static/bootstrap/js/bootstrap.min.js"></script>

  </body>
</html>