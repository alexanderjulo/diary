=====
Diary
=====

.. toctree::
   :maxdepth: 2

Diary can be your diary. Ar whatever you want. With a few tweaks,
you can easily make a blog out of it, or whatever you want.

I personally use it to write down little thoughts, that I do not wanna
loose, or when I am angry, or whatever. But that is just a matter of
personal preference.

I use it like many people use twitter, but for me personally and not to
entertain others.

Usage
=====
Well, you can either use `my instance`_ or setup your own diary. Either
way, how you use it, will not differ at all.

The handling is actually pretty easy. You sign up and choose a username
and a password (and confirm the password). Afterwards you will
be logged in and can click on "New Entry" in the navbar. Write whatever
you want and post it, finished. You can then edit, delete or whatever.

There are some links not working yet and a lot of features missing, but
that is how it basically works.

Setup & Configuration
=====================

Installation
------------
If you do want to setup your own, you can do as follows::

	$ git clone git@github.com:alexex/diary.git
	$ cd diary
	$ virtualenv venv
	$ source venv/bin/activate
	$ pip install -r requirements.txt

Configuration
-------------
Then you will have to create a `config.py` with two options::

	# The secret key to encrypt your cookies
	# choose something long with a lot of different characters
	SECRET_KEY='key'
	# The database uri
	SQLALCHEMY_DATABASE_URI='uri'

Afterwards you can run the following command::
	
	$ ./diary.py initdb

Deploy
------
Then you are ready to deploy. I ship a `.htaccess` with diary, so you
can easily start of with an apache. Just adapt the port to your needs
and start gunicorn::

	$ gunicorn --bind 127.0.0.1:53676 --workers 1 diary:app

If you want to deploy another way (fcgi, nginx or whatever) you will
need to work that out, but searching for deploy flask <method> should
give you quite enough of information to get everything going.

API
===
One day I will have implemented an API you can access and this way write
apps for diary instances, either mine or your personal one.

Source
======

.. toctree::
   :maxdepth: 2

.. automodule:: diary
	:members:



.. _my instance: http://diary.julo.ch/ 



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

