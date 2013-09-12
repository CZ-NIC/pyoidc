# -*- encoding:utf-8 -*-
from mako import runtime, filters, cache
UNDEFINED = runtime.UNDEFINED
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 8
_modified_time = 1378886695.840846
_enable_loop = True
_template_filename = 'htdocs/opbyuid.mako'
_template_uri = 'opbyuid.mako'
_source_encoding = 'utf-8'
_exports = []


def render_body(context,**pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        __M_writer = context.writer()
        # SOURCE LINE 1
        __M_writer(u'<!DOCTYPE html>\n\n<html>\n  <head>\n    <title>pyoidc RP</title>\n    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n    <!-- Bootstrap -->\n    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">\n      <link href="static/style.css" rel="stylesheet" media="all">\n\n    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->\n    <!--[if lt IE 9]>\n      <script src="../../assets/js/html5shiv.js"></script>\n      <script src="../../assets/js/respond.min.js"></script>\n    <![endif]-->\n  </head>\n  <body>\n\n    <!-- Static navbar -->\n    <div class="navbar navbar-default navbar-fixed-top">\n        <div class="navbar-header">\n          <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">\n            <span class="icon-bar"></span>\n            <span class="icon-bar"></span>\n            <span class="icon-bar"></span>\n          </button>\n          <a class="navbar-brand" href="#">pyoidc RP</a>\n        </div>\n        <div class="navbar-collapse collapse">\n          <ul class="nav navbar-nav">\n            <li><a href="/">Home</a></li>\n            <li><a href="oplist">OP list</a></li>\n            <li class="active"><a href="opbyuid">OP by unique id</a></li>\n          </ul>\n          <ul class="nav navbar-nav navbar-right">\n            <li><a href="about">About</a></li>\n          </ul>\n        </div><!--/.nav-collapse -->\n    </div>\n\n    <div class="container">\n     <!-- Main component for a primary marketing message or call to action -->\n      <div class="jumbotron">\n        <h1>OP by UID</h1>\n        <p>\n            You can perform a login to an OP\'s by using your unique identifier at the OP.\n            A unique identifier is defined as your username@opserver, this may be equal to an e-mail address.\n            A unique identifier is only equal to an e-mail address if the op server is published at the same\n            server address as your e-mail provider.\n        </p>\n        <form class="form-signin" action="rp" method="get">\n            <h2 class="form-signin-heading">Start sign in flow</h2>\n            <input type="text" id="uid" name="uid" class="form-control" placeholder="UID" autofocus>\n            <button class="btn btn-lg btn-primary btn-block" type="submit">Start</button>\n        </form>\n      </div>\n\n    </div> <!-- /container -->\n    <!-- jQuery (necessary for Bootstrap\'s JavaScript plugins) -->\n    <script src="/static/jquery.min.1.9.1.js"></script>\n    <!-- Include all compiled plugins (below), or include individual files as needed -->\n    <script src="/static/bootstrap/js/bootstrap.min.js"></script>\n\n\n  </body>\n</html>')
        return ''
    finally:
        context.caller_stack._pop_frame()


