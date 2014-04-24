# -*- encoding:utf-8 -*-
from mako import runtime, filters, cache
UNDEFINED = runtime.UNDEFINED
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 6
_modified_time = 1398247566.423659
_template_filename='htdocs/opresult.mako'
_template_uri='opresult.mako'
_template_cache=cache.Cache(__name__, _modified_time)
_source_encoding='utf-8'
_exports = []


# SOURCE LINE 3

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


def render_body(context,**pageargs):
    context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        userinfo = context.get('userinfo', UNDEFINED)
        __M_writer = context.writer()
        # SOURCE LINE 1
        __M_writer(u'<!DOCTYPE html>\n\n')
        # SOURCE LINE 38
        __M_writer(u'\n\n<html>\n  <head>\n    <title>pyoidc RP</title>\n    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n    <!-- Bootstrap -->\n    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">\n      <link href="static/style.css" rel="stylesheet" media="all">\n\n    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->\n    <!--[if lt IE 9]>\n      <script src="../../assets/js/html5shiv.js"></script>\n      <script src="../../assets/js/respond.min.js"></script>\n    <![endif]-->\n  </head>\n  <body>\n\n    <!-- Static navbar -->\n    <div class="navbar navbar-default navbar-fixed-top">\n        <div class="navbar-header">\n          <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">\n            <span class="icon-bar"></span>\n            <span class="icon-bar"></span>\n            <span class="icon-bar"></span>\n          </button>\n          <a class="navbar-brand" href="#">pyoidc RP</a>\n        </div>\n        <div class="navbar-collapse collapse">\n          <ul class="nav navbar-nav">\n          </ul>\n          <ul class="nav navbar-nav navbar-right">\n            <li><a href="logout">Logout</a></li>\n          </ul>\n        </div><!--/.nav-collapse -->\n    </div>\n\n    <div class="container">\n     <!-- Main component for a primary marketing message or call to action -->\n      <div class="jumbotron">\n        <h1>OP result</h1>\n        ')
        # SOURCE LINE 79
        __M_writer(unicode(create_result(userinfo)))
        __M_writer(u'\n      </div>\n\n    </div> <!-- /container -->\n    <!-- jQuery (necessary for Bootstrap\'s JavaScript plugins) -->\n    <script src="/static/jquery.min.1.9.1.js"></script>\n    <!-- Include all compiled plugins (below), or include individual files as needed -->\n    <script src="/static/bootstrap/js/bootstrap.min.js"></script>\n\n\n  </body>\n</html>')
        return ''
    finally:
        context.caller_stack._pop_frame()


