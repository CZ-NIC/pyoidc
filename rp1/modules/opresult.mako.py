# -*- encoding:utf-8 -*-
from mako import runtime, filters, cache
UNDEFINED = runtime.UNDEFINED
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 8
_modified_time = 1380202775.942127
_enable_loop = True
_template_filename = 'htdocs/opresult.mako'
_template_uri = 'opresult.mako'
_source_encoding = 'utf-8'
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

def createResult(result):
  """
      Creates a dropdown based on the service configurtion.
      """
  element = ""
  if result[0]:
    element += "<p>You have successfully loged in!</p>"
    element += "<div class='row'>"
    element += "<div class='col-md-10'>Accesstoken</div>"
    element += "</div>"
    element += "<div class='row'>"
    element += "<div class='col-md-10'>" + str(result[2]) + "</div>"
    element += "</div>"
    try:
        text = str(result[3].authorization_endpoint)
        element += "<div class='row'>"
        element += "<div class='col-md-3'>Authorization endpoint</div>"
        element += "<div class='col-md-7'>" + text + "</div>"
        element += "</div>"
    except:
        pass
    try:
        text = str(result[3].registration_endpoint)
        element += "<div class='row'>"
        element += "<div class='col-md-3'>Registration endpoint</div>"
        element += "<div class='col-md-7'>" + text + "</div>"
        element += "</div>"
    except:
        pass
    try:
        text = str(result[3].token_endpoint)
        element += "<div class='row'>"
        element += "<div class='col-md-3'>Token endpoint</div>"
        element += "<div class='col-md-7'>" + text + "</div>"
        element += "</div>"
    except:
        pass
    try:
        text = str(result[3].userinfo_endpoint)
        element += "<div class='row'>"
        element += "<div class='col-md-3'>User info endpoint</div>"
        element += "<div class='col-md-7'>" + text + "</div>"
        element += "</div>"
    except:
        pass
    for key, value in result[1].items():
        element += "<div class='row'>"
        element += "<div class='col-md-3'>" +  escape(unicode(key).encode("utf-8")) + "</div>"
        element += "<div class='col-md-7'>" + escape(unicode(value).encode("utf-8")) + "</div>"
        element += "</div>"
  else:
    element += "<p>You have failed to connect to the designated OP with the message:</p><p> " + result[1] + "</p>"
  return element


def render_body(context,**pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        result = context.get('result', UNDEFINED)
        __M_writer = context.writer()
        # SOURCE LINE 1
        __M_writer(u'<!DOCTYPE html>\n\n')
        # SOURCE LINE 79
        __M_writer(u'\n\n<html>\n  <head>\n    <title>pyoidc RP</title>\n    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n    <!-- Bootstrap -->\n    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">\n      <link href="static/style.css" rel="stylesheet" media="all">\n\n    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->\n    <!--[if lt IE 9]>\n      <script src="../../assets/js/html5shiv.js"></script>\n      <script src="../../assets/js/respond.min.js"></script>\n    <![endif]-->\n  </head>\n  <body>\n\n    <!-- Static navbar -->\n    <div class="navbar navbar-default navbar-fixed-top">\n        <div class="navbar-header">\n          <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">\n            <span class="icon-bar"></span>\n            <span class="icon-bar"></span>\n            <span class="icon-bar"></span>\n          </button>\n          <a class="navbar-brand" href="#">pyoidc RP</a>\n        </div>\n        <div class="navbar-collapse collapse">\n          <ul class="nav navbar-nav">\n          </ul>\n          <ul class="nav navbar-nav navbar-right">\n            <li><a href="logout">Logout</a></li>\n          </ul>\n        </div><!--/.nav-collapse -->\n    </div>\n\n    <div class="container">\n     <!-- Main component for a primary marketing message or call to action -->\n      <div class="jumbotron">\n        <h1>OP result</h1>\n        ')
        # SOURCE LINE 120
        __M_writer(unicode(createResult(result)))
        __M_writer(u'\n      </div>\n\n    </div> <!-- /container -->\n    <!-- jQuery (necessary for Bootstrap\'s JavaScript plugins) -->\n    <script src="/static/jquery.min.1.9.1.js"></script>\n    <!-- Include all compiled plugins (below), or include individual files as needed -->\n    <script src="/static/bootstrap/js/bootstrap.min.js"></script>\n\n\n  </body>\n</html>')
        return ''
    finally:
        context.caller_stack._pop_frame()


