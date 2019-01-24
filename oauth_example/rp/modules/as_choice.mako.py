from mako import cache
from mako import filters
from mako import runtime

UNDEFINED = runtime.UNDEFINED
STOP_RENDERING = runtime.STOP_RENDERING
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 10
_modified_time = 1474925155.284777
_enable_loop = True
_template_filename = 'htdocs/as_choice.mako'
_template_uri = 'as_choice.mako'
_source_encoding = 'utf-8'
_exports = []



def as_choice(as_list):
    """
    Creates a dropdown list of authorization servers
    """
    element = "<select name=\"authzsrv\">"
    for name in as_list:
        element += "<option value=\"%s\">%s</option>" % (name, name)
    element += "</select>"
    return element


def render_body(context,**pageargs):
    __M_caller = context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        action = context.get('action', UNDEFINED)
        method = context.get('method', UNDEFINED)
        as_list = context.get('as_list', UNDEFINED)
        __M_writer = context.writer()
        __M_writer('\n\n<html>\n  <head>\n    <title>OAuth2 RP Example</title>\n    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n    <!-- Bootstrap -->\n    <link href="static/bootstrap/css/bootstrap.min.css" rel="stylesheet" media="screen">\n    <link href="static/style.css" rel="stylesheet" media="all">\n\n    <!-- HTML5 shim and Respond.js IE8 support of HTML5 elements and media queries -->\n    <!--[if lt IE 9]>\n    <script src="../../assets/js/html5shiv.js"></script>\n    <script src="../../assets/js/respond.min.js"></script>\n    <style type="text/css">\n      tbody tr:nth-child(odd){ background-color:#ccc; }\n    </style>\n    <![endif]-->\n  </head>\n  <body>\n\n    <div class="container">\n     <!-- Main component for a primary marketing message or call to action -->\n      <div class="jumbotron">\n        <form action="')
        __M_writer(str(action))
        __M_writer('" method="')
        __M_writer(str(method))
        __M_writer('">\n            <h3>Choose the Authorization Server: </h3>\n            ')
        __M_writer(str(as_choice(as_list)))
        __M_writer('\n            <hr>\n            <br>\n            <input type="submit" name="commit" value="select"/>\n        </form>\n      </div>\n\n    </div> <!-- /container -->\n    <!-- jQuery (necessary for Bootstrap\'s JavaScript plugins) -->\n    <script src="/static/jquery.min.1.9.1.js"></script>\n    <!-- Include all compiled plugins (below), or include individual files as needed -->\n    <script src="/static/bootstrap/js/bootstrap.min.js"></script>\n\n  </body>\n</html>')
        return ''
    finally:
        context.caller_stack._pop_frame()


"""
__M_BEGIN_METADATA
{"source_encoding": "utf-8", "uri": "as_choice.mako", "line_map": {"16": 1, "48": 42, "36": 11, "37": 35, "38": 35, "39": 35, "40": 35, "41": 37, "42": 37, "28": 0}, "filename": "htdocs/as_choice.mako"}
__M_END_METADATA
"""
