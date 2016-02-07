#!/usr/bin/env python

import os
import re
import random
import hashlib
import hmac
import logging
import json
from string import letters

import jinja2
import webapp2

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'Rr38r.)2N7z=p[dC5AL9t"bmuU0vrUJb15<G.m+a8J5`%]pv.:+!"GrLebh7$x#'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
 
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)
        
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Two part cookie: User_key_id|Cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # If cookie value exists, check the value
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
    
    # Use the user ID as first part of cookie.
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))
    
    # Clear cookie on logout.
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
 
    # Initialized upon __init__ of Handler.
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id') # Check for user cookie
        self.user = uid and User.by_id(int(uid)) # If exists, store in user obj
    
    # Look up a specific version of a wiki page.
    def get_version(self, path):
        v = self.request.get('v')
        p = None
        if v:
            if v.isdigit():
                v = int(v)
                return Page.by_id(v, path)
                
            if not p:
                return self.notfound()

        else:
            return Page.get_page(path)

    def notfound(self):
        self.error(404)
        self.write('<h1>404: Not Found</h1>Sorry, that page does not exist.')


### Password functions ###        

def make_salt(length=64):
        return ''.join(random.choice(letters) for x in xrange(length))
        
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name+pw+salt).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, pw, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name, pw, salt)

### End password functions ###


# Create key for users, in case I create multiple wikis.    
def users_key(group = 'default'):
    return db.Key.from_path('users', group)
    
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    
    # Get user id. Use default group because only one wiki right now.
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())
    
    # If user with the input name exists, return the user obj, else return None.
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name) # Check if user exists
        if u and valid_pw(name, pw, u.pw_hash): # Check if login pw is valid
            return u
    
    # When user signs up, create password hash based on input password
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name, 
                    pw_hash = pw_hash, 
                    email = email)


### Form validation functions ###
                    
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PW_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PW_RE.match(password)

VERIFY_RE = re.compile(r"^.{3,20}$")
def valid_verify(verify):
    return verify and VERIFY_RE.match(verify)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)

### End form validation functions ###


class Page(db.Model):
    content = db.TextProperty()
    version = db.IntegerProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
    # Get latest version of a page, using memcache.
    @staticmethod
    def get_page(path):
        page = memcache.get(path)
        if page is not None:
            return page
        else:
            page = Page.by_path(path).get()
            memcache.set(path, page)
            return page
    
    # Organizes versions of a wiki page based on the page path.
    @staticmethod
    def parent_key(path):
        return db.Key.from_path('/root' + path, 'pages')
    
    # Set Page.version based on how many versions of the page already exist. 
    def set_version(self, path):
        q = Page.by_path(path)
        q = list(q)
        self.version = len(q) + 1

    # Get all pages by path, sorted by creation time.         
    @classmethod
    def by_path(cls, path):
        q = cls.all()
        q.ancestor(cls.parent_key(path))
        q.order("-created")
        return q
    
    # Get a specific version of a page.
    @classmethod
    def by_id(cls, version, path):
        q = Page.by_path(path)
        v = q.filter('version =', version).get()
        return v

class Signup(Handler):
    def get(self):
        next_url = self.request.headers.get('referer', '/')
        self.render("signup.html", next_url = next_url)

    def post(self):
        have_error = False
        
        next_url = str(self.request.get('next_url'))
        if not next_url or next_url.startswith('/login'):
            next_url = '/'
        
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        
        if have_error:
            self.render('signup.html', **params)
        else:
            u = User.by_name(self.username)
            if u:
                error = "That user already exists."
                self.render('signup.html', error_user_exists = error)
            else:
                u = User.register(self.username, self.password, self.email)
                u.put()

                self.login(u)
                self.redirect(next_url)


class Login(Handler):
    def get(self):
        next_url = self.request.headers.get('referer', '/')
        self.render("login.html", next_url = next_url)

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        
        next_url = str(self.request.get('next_url'))

        if not next_url or next_url.startswith('/login'):
            next_url = '/'

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect(next_url)
        else:
            error = "Invalid login"
            self.render("login.html", error = error)    


class Logout(Handler):
    def get(self):
        next_url = self.request.headers.get('referer', '/')
        self.logout()
        return self.redirect(next_url)

        
class WikiPage(Handler):
    def get(self, path):

        page = self.get_version(path)

        if page:
            self.render("page.html", page = page, path = path)
        else:
            self.redirect("/_edit" + path)


class EditPage(Handler):
    def get(self, path):
        if not self.user:
            self.redirect("/login")
        
        page = self.get_version(path)

        try:
            content = page.content
        except AttributeError:
            content = ""
        self.render("edit.html", path = path, content = content)    

    def post(self, path):
        if not self.user:
            self.error(400)
            return

        content = self.request.get("content")
        old_page = Page.by_path(path).get()
        
        if not (old_page or content):
            return
        elif not old_page or old_page.content != content:
            page = Page(parent = Page.parent_key(path), content = content)
            page.set_version(path)
            page.put()
            memcache.set(path, page)

        self.redirect(path)


class HistoryPage(Handler):
    def get(self, path):
        q = Page.by_path(path)
        q.fetch(limit = 100)
        
        posts = list(q)
        if posts:
            self.render("history.html", path = path, posts = posts)
        else:
            self.redirect("/_edit" + path)

            
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_history' + PAGE_RE, HistoryPage),
                               ('/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=True)
                              
def delete_all():
    q = Page.all().fetch(1000)
    db.delete(q)
    memcache.flush_all()

# WARNING: Uncommenting this next line deletes all wiki posts! 
# delete_all()