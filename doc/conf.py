import alabaster
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinxcontrib.autodoc_pydantic',
]

autoclass_content = 'both'  # Merge the __init__ docstring into the class docstring.
autodoc_member_order = 'bysource'  # Order by source ordering
autodoc_pydantic_model_show_config = True
autodoc_pydantic_settings_show_json = False

templates_path = ['_templates']

source_suffix = '.rst'

master_doc = 'index'

project = u'pyoidc'

copyright = u'2014, Roland Hedberg'

version = '0.1'

release = '0.1'

exclude_patterns = ['_build']

pygments_style = 'sphinx'

html_theme_path = [alabaster.get_path()]

html_theme = 'alabaster'

html_static_path = ['_static']

htmlhelp_basename = 'pyoidcdoc'

html_theme_options = {
   'description': '',
   'github_button': False,
   'github_user': 'its-dirg',
   'github_repo': 'saml2testGui',
   'github_banner': False,

}

html_sidebars = {
   '**': [
       'about.html',
       'navigation.html',
       'searchbox.html',
       'donate.html',
   ]
}

man_pages = [
    ('index', 'pyoidc', u'pyoidc Documentation',
     [u'Roland Hedberg'], 1)
]

latex_elements = {}

latex_documents = [
  ('index', 'pyoidc.tex', u'pyoidc Documentation',
   u'Roland Hedberg', 'manual'),
]

texinfo_documents = [
  ('index', 'pyoidc', u'pyoidc Documentation',
   u'Roland Hedberg', 'pyoidc', 'One line description of project.',
   'Miscellaneous'),
]
