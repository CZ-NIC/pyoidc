# -*- encoding:utf-8 -*-
from mako import runtime, filters, cache
UNDEFINED = runtime.UNDEFINED
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 8
_modified_time = 1378901631.691583
_enable_loop = True
_template_filename = 'htdocs/oplist.mako'
_template_uri = 'oplist.mako'
_source_encoding = 'utf-8'
_exports = []


# SOURCE LINE 3

def createDropdown(service):
  """
      Creates a dropdown based on the service configurtion.
      """
  element = ""
  for key, _dict in service.items():
    element += '<a class="list-group-item" href="/rp?key=' + key + '">' + _dict['description'] + '</a>'
  return element


def render_body(context,**pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        service = context.get('service', UNDEFINED)
        __M_writer = context.writer()
        # SOURCE LINE 1
        __M_writer(u'<!DOCTYPE html>\n\n')
        # SOURCE LINE 12
        __M_writer(u'\n\n<html>\n  <head>\n    <title>pyoidc RP</title>\n    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n    <!-- Bootstrap -->\n    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">\n      <link href="static/style.css" rel="stylesheet" media="all">\n\n    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->\n    <!--[if lt IE 9]>\n      <script src="../../assets/js/html5shiv.js"></script>\n      <script src="../../assets/js/respond.min.js"></script>\n    <![endif]-->\n  </head>\n  <body>\n\n    <!-- Static navbar -->\n    <div class="navbar navbar-default navbar-fixed-top">\n        <div class="navbar-header">\n          <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">\n            <span class="icon-bar"></span>\n            <span class="icon-bar"></span>\n            <span class="icon-bar"></span>\n          </button>\n          <a class="navbar-brand" href="#">pyoidc RP</a>\n        </div>\n        <div class="navbar-collapse collapse">\n          <ul class="nav navbar-nav">\n            <li><a href="/">Home</a></li>\n            <li class="active"><a href="oplist">OP list</a></li>\n            <li><a href="opbyuid">OP by unique id</a></li>\n          </ul>\n          <ul class="nav navbar-nav navbar-right">\n            <li><a href="about">About</a></li>\n          </ul>\n        </div><!--/.nav-collapse -->\n    </div>\n\n    <div class="container">\n     <!-- Main component for a primary marketing message or call to action -->\n      <div class="jumbotron">\n        <h1>OP list</h1>\n        <p>You can perform a login to any of the listed OP\'s.</p>\n        <div class="list-group">\n          <a href="#" class="list-group-item active">OP list</a>\n          ')
        # SOURCE LINE 59
        __M_writer(unicode(createDropdown(service)))
        __M_writer(u'\n        </div>\n\n      </div>\n\n    </div> <!-- /container -->\n    <!-- jQuery (necessary for Bootstrap\'s JavaScript plugins) -->\n    <script src="/static/jquery.min.1.9.1.js"></script>\n    <!-- Include all compiled plugins (below), or include individual files as needed -->\n    <script src="/static/bootstrap/js/bootstrap.min.js"></script>\n\n\n  </body>\n</html>')
        return ''
    finally:
        context.caller_stack._pop_frame()


