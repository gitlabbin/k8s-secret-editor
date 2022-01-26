from flask_wtf import Form

from wtforms import RadioField


class SearchForm(Form):
    namespace = RadioField('Namespace')
