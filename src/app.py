# -*- coding: utf-8 -*-
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import yaml
from flask import redirect, request, jsonify, render_template, url_for, \
    make_response, flash
from flask import Flask
import requests
from requests_oauthlib import OAuth1
from flask_jsonlocale import Locales
from flask_mwoauth import MWOAuth
from SPARQLWrapper import SPARQLWrapper, JSON
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__, static_folder='../static')

# Load configuration from YAML file
__dir__ = os.path.dirname(__file__)
app.config.update(
    yaml.safe_load(open(os.path.join(__dir__, os.environ.get(
        'FLASK_CONFIG_FILE', 'config.yaml')))))
locales = Locales(app)
_ = locales.get_message

db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)

class Wiki(db.Model):
    _sitematrix = None
    id = db.Column(db.Integer, primary_key=True)
    dbname = db.Column(db.String(255))
    url_ = db.Column(db.String(255))
    featured_articles_category = db.Column(db.String(255))
    bytes_per_link_avg = db.Column(db.Integer)
    bytes_per_link_max = db.Column(db.Integer)
    minimum_length = db.Column(db.Integer)
    articles = db.relationship('SuggestedArticle', backref='suggested_article', lazy=True)

    def _get_sitematrix_match(self):
        if self._sitematrix:
            return self._sitematrix
        sitematrix = mwoauth.request({
            "action": "sitematrix",
            "format": "json"
        }).get('sitematrix', {})
        if 'count' in sitematrix:
            del sitematrix['count']
        for lang in sitematrix:
            for wiki in sitematrix[lang]['site']:
                if wiki['dbname'] == self.dbname:
                    self._sitematrix = wiki
                    return wiki

    @property
    def url(self):
        if self.url_:
            return self.url_
        sm = self._get_sitematrix_match()
        self.url_ = sm['url']
        db.session.commit()
        return self.url_
    
    @property
    def name(self):
        sm = self._get_sitematrix_match()
        print(sm)
        return '%s (%s)' % (sm['sitename'], sm['dbname'])

class SuggestedArticle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wiki_id = db.Column(db.Integer, db.ForeignKey('wiki.id'), nullable=False)
    pass

mwoauth = MWOAuth(
    consumer_key=app.config.get('CONSUMER_KEY'),
    consumer_secret=app.config.get('CONSUMER_SECRET'),
    base_url=app.config.get('OAUTH_MWURI'),
    return_json=True
)
app.register_blueprint(mwoauth.bp)

def logged():
    return mwoauth.get_current_user() is not None

def get_user():
    if logged():
        return User.query.filter_by(username=mwoauth.get_current_user()).first()
    return None

@app.context_processor
def inject_base_variables():
    return {
        "logged": logged(),
        "username": mwoauth.get_current_user(),
        "is_admin": get_user().is_admin
    }

@app.before_request
def force_login():
    if not logged() and '/login' not in request.url and '/oauth-callback' not in request.url:
        return render_template('login.html')

@app.before_request
def db_check_user():
    if logged():
        user = get_user()
        if user is None:
            user = User(username=mwoauth.get_current_user())
            db.session.add(user)
            db.session.commit()
        else:
            if not user.is_active:
                return render_template('permission_denied.html')

@app.before_request
def db_admin_permissions():
    if logged() and '/admin' in request.url and not get_user().is_admin:
        return render_template('permission_denied.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
def admin_home():
    return render_template('admin/index.html')

@app.route('/admin/wikis', methods=['GET', 'POST'])
def admin_wikis():
    sitematrix = mwoauth.request({
        "action": "sitematrix",
        "format": "json"
    }).get('sitematrix', {})
    if 'count' in sitematrix:
        del sitematrix['count']
    if request.method == 'POST':
        wiki = Wiki(
            dbname=request.form.get('dbname'),
            featured_articles_category=request.form.get('featured-category')
        )
        db.session.add(wiki)
        db.session.commit()
        return redirect(url_for('admin_wikis'))
    return render_template('admin/wikis.html', wikis=Wiki.query.all(), sitematrix=sitematrix)

@app.route('/admin/wikis/<int:id>/delete', methods=['POST'])
def admin_wiki_delete(id):
    w = Wiki.query.filter_by(id=id).first()
    db.session.delete(w)
    db.session.commit()
    flash(_('wiki-deleted'), 'success')
    return redirect(url_for('admin_wikis'))

@app.route('/admin/wikis/<int:id>/edit', methods=['GET', 'POST'])
def admin_wiki_edit(id):
    w = Wiki.query.filter_by(id=id).first()
    if request.method == 'POST':
        w.featured_articles_category = request.form.get('featured-category')
        w.minimum_length = request.form.get('minimum-length')
        db.session.commit()
        return redirect(request.url)
    return render_template('admin/wiki.html', wiki=w)

@app.route('/admin/wikis/<int:id>/metrics', methods=['POST'])
def admin_wiki_metrics(id):
    w = Wiki.query.filter_by(id=id).first()
    w.bytes_per_link_avg = request.form.get('avg-bytes-per-link')
    w.bytes_per_link_max = request.form.get('max-bytes-per-link')
    db.session.commit()
    flash(_('wiki-metrics-edited'), 'success')
    return redirect(url_for('admin_wiki_edit', id=id))

@app.route('/test')
def test():
    return Wiki.query.all()[0].sitename

if __name__ == "__main__":
    app.run(threaded=True)