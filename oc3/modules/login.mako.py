# -*- encoding:utf-8 -*-
from mako import runtime, filters, cache
UNDEFINED = runtime.UNDEFINED
__M_dict_builtin = dict
__M_locals_builtin = locals
_magic_number = 6
_modified_time = 1347268264.441828
_template_filename='htdocs/login.mako'
_template_uri='login.mako'
_template_cache=cache.Cache(__name__, _modified_time)
_source_encoding='utf-8'
_exports = ['add_js', 'title']


def _mako_get_namespace(context, name):
    try:
        return context.namespaces[(__name__, name)]
    except KeyError:
        _mako_generate_namespaces(context)
        return context.namespaces[(__name__, name)]
def _mako_generate_namespaces(context):
    pass
def _mako_inherit(template, context):
    _mako_generate_namespaces(context)
    return runtime._inherit_from(context, u'root.mako', _template_uri)
def render_body(context,**pageargs):
    context.caller_stack._push_frame()
    try:
        __M_locals = __M_dict_builtin(pageargs=pageargs)
        logo_url = context.get('logo_url', UNDEFINED)
        policy_url = context.get('policy_url', UNDEFINED)
        sid = context.get('sid', UNDEFINED)
        action = context.get('action', UNDEFINED)
        login = context.get('login', UNDEFINED)
        password = context.get('password', UNDEFINED)
        __M_writer = context.writer()
        # SOURCE LINE 1
        __M_writer(u'\n')
        # SOURCE LINE 2
        __M_writer(u'\n\n<div class="login_form" class="block">\n    <form action="')
        # SOURCE LINE 5
        __M_writer(unicode(action))
        __M_writer(u'" method="post" class="login form">\n        <input type="hidden" name="sid" value="')
        # SOURCE LINE 6
        __M_writer(unicode(sid))
        __M_writer(u'"/>\n        <table>\n            <tr>\n                <td>Username</td>\n                <td><input type="text" name="login" value="')
        # SOURCE LINE 10
        __M_writer(unicode(login))
        __M_writer(u'"/></td>\n            </tr>\n            <tr>\n                <td>Password</td>\n                <td><input type="password" name="password"\n                value="')
        # SOURCE LINE 15
        __M_writer(unicode(password))
        __M_writer(u'"/></td>\n            </tr>\n            <tr>\n                </td>\n                <td><input type="submit" name="form.commit"\n                        value="Log In"/></td>\n            </tr>\n        </table>\n    </form>\n')
        # SOURCE LINE 24
        if logo_url:
            # SOURCE LINE 25
            __M_writer(u'        <img src="')
            __M_writer(unicode(logo_url))
            __M_writer(u'" alt="Client logo">\n')
            pass
        # SOURCE LINE 27
        if policy_url:
            # SOURCE LINE 28
            __M_writer(u'         <a href="')
            __M_writer(unicode(policy_url))
            __M_writer(u'"><b>Client policy</b></a>\n')
            pass
        # SOURCE LINE 30
        __M_writer(u'</div>\n\n')
        # SOURCE LINE 38
        __M_writer(u'\n')
        return ''
    finally:
        context.caller_stack._pop_frame()


def render_add_js(context):
    context.caller_stack._push_frame()
    try:
        __M_writer = context.writer()
        # SOURCE LINE 32
        __M_writer(u'\n    <script type="text/javascript">\n        $(document).ready(function() {\n            bookie.login.init();\n        });\n    </script>\n')
        return ''
    finally:
        context.caller_stack._pop_frame()


def render_title(context):
    context.caller_stack._push_frame()
    try:
        __M_writer = context.writer()
        # SOURCE LINE 2
        __M_writer(u'Log in')
        return ''
    finally:
        context.caller_stack._pop_frame()


