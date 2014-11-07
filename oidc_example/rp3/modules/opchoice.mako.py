# -*- coding:utf-8 -*-
from mako import runtime

UNDEFINED = runtime.UNDEFINED
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 9
_modified_time = 1400148619.346786
_enable_loop = True
_template_filename = 'htdocs/opchoice.mako'
_template_uri = 'opchoice.mako'
_source_encoding = 'utf-8'
_exports = []


# SOURCE LINE 1

def op_choice(op_list):
    """
    Creates a dropdown list of OpenID Connect providers
    """
    element = "<select name=\"op\">"
    for name in op_list:
        element += "<option value=\"%s\">%s</option>" % (name, name)
    element += "</select>"
    return element


def render_body(context, **pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        op_list = context.get('op_list', UNDEFINED)
        __M_writer = context.writer()
        # SOURCE LINE 11
        __M_writer(
            u'\n\n<!DOCTYPE html>\n\n<html>\n  <head>\n    <title>pyoidc RP</title>\n    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n    <!-- Bootstrap -->\n    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">\n      <link href="static/style.css" rel="stylesheet" media="all">\n\n    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->\n    <!--[if lt IE 9]>\n      <script src="../../assets/js/html5shiv.js"></script>\n      <script src="../../assets/js/respond.min.js"></script>\n    <![endif]-->\n  </head>\n  <body>\n\n    <!-- Static navbar -->\n    <div class="navbar navbar-default navbar-fixed-top">\n        <div class="navbar-header">\n          <a class="navbar-brand" href="#">pyoidc RP</a>\n        </div>\n    </div>\n\n    <div class="container">\n     <!-- Main component for a primary marketing message or call to action -->\n      <div class="jumbotron">\n        <form class="form-signin" action="rp" method="get">\n        <h1>OP by UID</h1>\n          <h3>Chose the OpenID Connect Provider: </h3>\n            <p>From this list</p>\n            ')
        # SOURCE LINE 45
        __M_writer(unicode(op_choice(op_list)))
        __M_writer(
            u'\n            <p> OR by providing your unique identifier at the OP. </p>\n            <input type="text" id="uid" name="uid" class="form-control" placeholder="UID" autofocus>\n            <button class="btn btn-lg btn-primary btn-block" type="submit">Start</button>\n        </form>\n      </div>\n\n    </div> <!-- /container -->\n    <!-- jQuery (necessary for Bootstrap\'s JavaScript plugins) -->\n    <script src="/static/jquery.min.1.9.1.js"></script>\n    <!-- Include all compiled plugins (below), or include individual files as needed -->\n    <script src="/static/bootstrap/js/bootstrap.min.js"></script>\n\n  </body>\n</html>')
        return ''
    finally:
        context.caller_stack._pop_frame()


