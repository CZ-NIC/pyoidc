"""Implementation of basic templating engine."""

FORM_POST = """<html>
  <head>
    <title>Submit This Form</title>
  </head>
  <body onload="javascript:document.forms[0].submit()">
    <form method="post" action="{action}">
        {html_inputs}
    </form>
  </body>
</html>"""


def inputs(form_args):
    """Create list of input elements."""
    element = []
    for name, value in form_args.items():
        element.append('<input type="hidden" name="{}" value="{}"/>'.format(name, value))
    return "\n".join(element)


class TemplateException(Exception):
    """Custom exception from TemplateEngine."""


def render_template(template_name, context):
    """Render specified template with the given context.

    Templates are defined as strings in this module.
    """
    if template_name == 'form_post':
        if 'action' not in context:
            raise TemplateException('Missing action in context.')
        context['html_inputs'] = inputs(context.get('inputs', {}))
        return FORM_POST.format(**context)
    elif template_name == 'verify_logout':
        return ''
    raise TemplateException('Unknown template name.')
