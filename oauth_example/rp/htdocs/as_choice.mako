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
    <link href="static/style.css" rel="stylesheet" media="all">
    <style type="text/css">
      tbody tr:nth-child(odd){ background-color:#ccc; }
    </style>
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
    </div> 
  </body>
</html>
