#!/usr/bin/env python2.7
from flask import Flask, request, Response, render_template, redirect, \
	url_for, abort, flash
from flask.views import MethodView
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.wtf import Form
from flask.ext.login import LoginManager, login_user, logout_user, current_user, login_required
from flask.ext.bcrypt import Bcrypt
from flask.ext.script import Manager
from jinja2.filters import do_mark_safe as safe
from wtforms import fields, validators, ValidationError
from markdown import markdown
from datetime import datetime, date, time
from functools import wraps
import json

app = Flask(__name__)

app.config.from_object(__name__)
app.config.from_pyfile('config.py', silent=True)

db = SQLAlchemy(app)

login = LoginManager()
login.setup_app(app)

bcrypt = Bcrypt(app)

manager = Manager(app)



"""
	Database Models
	~~~~~~~~~~~~~~~
"""
class User(db.Model):
	"""The user class is used to store a email/password combination
	and determine which entries belong to which user. This makes it
	possible to have multiple users use the same diary instance."""
	id = db.Column(db.Integer, primary_key=True)
	
	username = db.Column(db.String(30), unique=True)
	password = db.Column(db.String(60))
	
	authenticated = db.Column(db.Boolean())
	active = db.Column(db.Boolean())
	
	def __init__(self, username, password):
		self.username = username
		self.password = bcrypt.generate_password_hash(password)
		self.active = True
		self.authenticated = False
	
	def authenticate(self, password):
		return bcrypt.check_password_hash(self.password, password)
	
	def is_authenticated(self):
		return self.authenticated
		
	def is_active(self):
		return self.active
		
	def is_anonymous(self):
		return False
		
	def get_id(self):
		return self.id

class Entry(db.Model):
	"""The main content class. Every entry in every diary consists
	of an entry instance with optional attachments."""
	
	id = db.Column(db.Integer, primary_key=True)
	
	owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	
	date = db.Column(db.Date)
	time = db.Column(db.Time)
	
	title = db.Column(db.String(255))
	
	markup = db.Column(db.Text)
	html = db.Column(db.Text)
	
	public = db.Column(db.Boolean)
	
	def __html__(self):
		"""Enable the entry to be used as {{ entry }} in templates. This
		property will return the html body of the entry in that case."""
		return self.html
Entry.owner = db.relationship('User', backref=db.backref('entry', lazy='dynamic'))

class Attachment(db.Model):
	"""This class is carrying the attachments. It is always connected to
	entries."""
	id = db.Column(db.Integer, primary_key=True)

	entry_id = db.Column(db.Integer, db.ForeignKey('entry.id'))

	filename = db.Column(db.String(255))
Attachment.entry = db.relationship('Entry', backref=db.backref('entry', lazy='dynamic'))



"""
	Forms
	~~~~~
"""
class SignUpForm(Form):
	username = fields.TextField('Username')
	password = fields.PasswordField('Password', [validators.Required()])
	confirm = fields.PasswordField('Confirm', [validators.Required()])

	def validate_username(form, field):
		used = User.query.filter_by(username=form.data['username']).first()
		if used:
			raise ValidationError('Username is in use already.')

	def validate_confirm(form, field):
		if not form.data['password'] == form.data['confirm']:
			raise ValidationError('The password do not match.')

class LoginForm(Form):
	username = fields.TextField('Username')
	password = fields.PasswordField('Password')

	def validate_username(form, field):
		user = User.query.filter_by(username=form.data['username']).first()
		if not user:
			raise ValidationError('Username does not exist.')

	def validate_password(form, field):
		user = User.query.filter_by(username=form.data['username']).first()
		if not user or not user.authenticate(form.data['password']):
			raise ValidationError('Username and password do not match.')
	
class EntryForm(Form):
	title = fields.TextField('Title')
	markup = fields.TextAreaField('Markup', [validators.Required()])
	public = fields.BooleanField('Make this entry public')



"""
	Helpers/Tools
	~~~~~~~~~~~~~
"""
@login.user_loader
def load_user(userid):
	return User.query.get(userid)

def render_bs_input(input, disabled=False, override=None, **param):
	return safe(render_template('bootstrap_input.html', input=input, disabled=disabled, override=override, param=param))

@app.context_processor
def inject_tools():
	return dict(render_bs_input=render_bs_input)

def auth_check(username, password):
	user = User.query.filter_by(username=username).first()
	if not user or not user.authenticate(password):
		return False
	else:
		return True

def auth_missing():
	return Response(
		'Could not verify your access level for that URL.\n'
		'You have to login with proper credentials', 401,
		{'WWW-Authenticate': 'Basic realm="Login Required"'})

def auth_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		 auth = request.authorization
		 if not auth or not auth_check(auth.username, auth.password):
		 	return auth_missing()
		 return f(*args, **kwargs)
	return decorated



"""
	Routes
	~~~~~~
"""


"""
	Webinterface
	------------
"""
@app.route('/signup/', methods=['GET', 'POST'])
def signup():
	form = SignUpForm()
	if form.validate_on_submit():
		user = User(form.data['username'], form.data['password'])
		db.session.add(user)
		db.session.commit()
		user.authenticated = True
		login_user(user)
		db.session.commit()
		flash('Thank you for signing up. You have been logged in already!', 'success')
		return redirect(url_for('index'))
	else:
		return render_template('signup.html', form=form)

@login.unauthorized_handler
@app.route('/about/')
def about():
	return render_template('about.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.data['username']).first()
		login_user(user)
		user.authenticated = True
		db.session.commit()
		flash('You were logged in successfully.', 'success')
		return redirect(url_for('index'))
	else:
		return render_template('login.html', form=form)
		
@app.route('/settings/', methods=['GET', 'POST'])
@login_required
def settings():
	form = SettingsForm()
	pass
		
@app.route('/logout/')
@login_required
def logout():
	logout_user()
	current_user.authenticated = False
	db.session.commit()
	flash('You have been logged out.', 'success')
	return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
	days = Entry.query.filter_by(owner_id=current_user.id).order_by(db.desc('date')).group_by('date').all()
	i = 0
	for day in days:
		days[i] = {'date': day.date, 'entries': Entry.query.filter_by(owner_id=current_user.id, date=day.date).order_by(db.desc('time')).all()}
		i = i+1
	return render_template('index.html', entries=days, user=current_user)
	
@app.route('/view/<int:entryid>/')
@login_required
def view(entryid):
	entry = Entry.query.get_or_404(entryid)
	if not entry.owner_id == current_user.id:
		return abort(403)
	return render_template('view.html', entry=entry)
	
@app.route('/submit/', methods=['GET', 'POST'])
@login_required
def submit():
	form = EntryForm()
	if form.validate_on_submit():
		entry = Entry()
		form.populate_obj(entry)
		entry.html = markdown(entry.markup, safe_mode="remove")
		now = datetime.now()
		entry.owner_id = current_user.id
		entry.date = now.date()
		entry.time = now.time()
		db.session.add(entry)
		db.session.commit()
		flash('Your entry has been submitted.', 'success')
		return redirect(url_for('index'))
	else:
		return render_template('submit.html', form=form)
		
@app.route('/edit/<int:entryid>/', methods=['GET', 'POST'])
@login_required
def edit(entryid):
	entry = Entry.query.get_or_404(entryid)
	if not current_user.id == entry.owner_id:
		abort(403)
	form = EntryForm(obj=entry)
	if form.validate_on_submit():
		form.populate_obj(entry)
		entry.html = markdown(entry.markup)
		db.session.commit()
		flash('Your entry has been edited.', 'success')
		return redirect(url_for('index'))
	else:
		return render_template('edit.html', form=form, entry=entry)
		
@app.route('/delete/<int:entryid>/')
@login_required
def delete(entryid):
	entry = Entry.query.get_or_404(entryid)
	if not current_user.id == entry.owner_id:
		abort(403)
	db.session.delete(entry)
	db.session.commit()
	flash('Your entry has been deleted.', 'success')
	return redirect(url_for('index'))



"""
	Command Line Interface
	~~~~~~~~~~~~~~~~~~~~~~
"""
@manager.command
def initdb():
	"""Initiate all tables in the database."""
	db.create_all()

if __name__ == '__main__':
	manager.run()