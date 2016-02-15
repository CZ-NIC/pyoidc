<!DOCTYPE html>

<%!
    from html import entities as htmlentitydefs
    import re

    # this pattern matches substrings of reserved and non-ASCII characters
    pattern = re.compile(r"[&<>\"\x80-\xff]+")

    # create character map
    entity_map = {}

    for i in range(256):
        entity_map[chr(i)] = "&#%d;" % i

    for entity, char in htmlentitydefs.entitydefs.items():
        if char in entity_map:
            entity_map[char] = "&%s;" % entity

    def escape_entity(m, get=entity_map.get):
        return "".join(map(get, m.group()))

    def escape(string):
        return pattern.sub(escape_entity, string)

    def create_result(userinfo, user_id, id_token):
        """
        Creates a display of user information.
        """
        element = "<h3>You have successfully authenticated!</h3>"
        if id_token:
          element += '<h3>With the following authentication information</h3>'
          for key, value in id_token.items():
              element += "<div class='row'>"
              element += "<div class='col-md-3'>" +  escape(str(key)) + "</div>"
              element += "<div class='col-md-7'>" + escape(str(value)) + "</div>"
              element += "</div>"
        if user_id:
          element += '<h3>And are now known to the RP as:</h3>'
          element += '<i>'+userid+'</i>'
        if userinfo:
          element += '<h3>With the following user information</h3>'
          for key, value in userinfo.items():
              element += "<div class='row'>"
              element += "<div class='col-md-3'>" +  escape(str(key)) + "</div>"
              element += "<div class='col-md-7'>" + escape(str(value)) + "</div>"
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
        ${create_result(userinfo, user_id, id_token)}
    </div>

</div>
<!-- /container -->


% if check_session_iframe_url is not UNDEFINED:
    <iframe id="rp_iframe" src="/session_iframe" hidden></iframe>
    <iframe id="op_iframe" src="${check_session_iframe_url}" hidden></iframe>
% endif


<!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
<script src="/static/jquery.min.1.9.1.js"></script>
<!-- Include all compiled plugins (below), or include individual files as needed -->
<script src="/static/bootstrap/js/bootstrap.min.js"></script>


</body>
</html>