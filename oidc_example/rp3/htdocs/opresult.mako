<!DOCTYPE html>

    <%!
        import htmlentitydefs
        import re, string

        # this pattern matches substrings of reserved and non-ASCII characters
        pattern = re.compile(r"[&<>\"\x80-\xff]+")

        # create character map
        entity_map = {}

        for i in range(256):
        entity_map[chr(i)] = "&#%d;" % i

        for entity, char in htmlentitydefs.entitydefs.items():
        if entity_map.has_key(char):
            entity_map[char] = "&%s;" % entity

        def escape_entity(m, get=entity_map.get):
        return string.join(map(get, m.group()), "")

        def escape(string):
        return pattern.sub(escape_entity, string)

        def create_result(userinfo):
      """
      Creates a display of user information.
      """
      element = "<p>You have successfully authenticated!</p>"

      for key, value in userinfo.items():
          element += "<div class='row'>"
          element += "<div class='col-md-3'>" +  escape(unicode(key).encode("utf-8")) + "</div>"
          element += "<div class='col-md-7'>" + escape(unicode(value).encode("utf-8")) + "</div>"
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
        </ul>
        <ul class="nav navbar-nav navbar-right">
            <li><a href="logout">Logout</a></li>
        </ul>
    </div>
    <!--/.nav-collapse -->
</div>

<div class="container">
    <!-- Main component for a primary marketing message or call to action -->
    <div class="jumbotron">
        <h1>OP result</h1>
        ${create_result(userinfo)}
    </div>

</div>
<!-- /container -->
<!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
<script src="/static/jquery.min.1.9.1.js"></script>
<!-- Include all compiled plugins (below), or include individual files as needed -->
<script src="/static/bootstrap/js/bootstrap.min.js"></script>


</body>
</html>