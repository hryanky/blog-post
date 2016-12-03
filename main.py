#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
import re
import hashlib
import hmac
from string import letters
import random
from google.appengine.ext import db
import main


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
autoescape = True)

secret = 'somerandomstring'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class Handler(webapp2.RequestHandler):
    def write(self,*a,**kw):
        self.response.out.write(*a,**kw)
    def render_str(self,template,**params):
        t=jinja_env.get_template(template)
        return t.render(params)
        
    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        #print name
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self,*a,**kw):
        webapp2.RequestHandler.initialize(self,*a,**kw)
        u = self.read_secure_cookie('user_id')
        self.user = u and User.by_id(int(u))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class User(db.Model):
    name = db.StringProperty(required = True)
    pwd_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        #u = User.all()
        #u.filter("name=","name")
        #u = db.GqlQuery("SELECT * FROM User WHERE name = " , name)
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pwd_hash = make_pw_hash(name, pw)
        return User(name = name,
                    pwd_hash = pwd_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        print name , pw
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pwd_hash):
            print "valid", name
            return u

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

class MainHandler(Handler):
    def get(self):
        self.render("login.html")
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
 
        if username and password:
            self.redirect("/welcome?username=" + username)
        else:
            self.render("login.html", error="Invalid login")           
 
        
class WelcomeHandler(Handler):
    def get(self):
        print self.user
       # uid = self.read_secure_cookie('user_id')
        #user = uid and User.by_id(int(uid))
        if self.user:
            print "render"
            self.render("welcome.html", username=self.user.name) #self.user.name
        else:
            print "redirect"
            self.redirect("/signup")

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class SignUpHandler(Handler):
    def get(self):
        print "signup getting signup html"
        self.render("signup.html")
    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        params = dict(username=self.username)
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
            print "signup done"
            self.done()
            #self.redirect('/register', **params)

    def done(self, *a, **kw):
        print "Hi......"
        raise NotImplementedError

class RegisterHandler(SignUpHandler):
    def done(self,*a, **kw):

        # check if User exists already
        u = User.by_name(self.username)
        print "register done for: "
        print u
        if u:
            print "register already done for that user"
            error_message = 'That user already exists.'
            self.render('signup.html', error_username=error_message)
        else:
            print "registering user"
            u = User.register(self.username, self.password, self.email)
            u.put()
            #self.set_secure_cookie('user_id', str(User.key().id()))
            self.login(u)
            print "redirect to welcome"
            self.redirect('/welcome')

class LoginHandler(Handler):
    def get(self):
        self.render("login.html")
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        user = User.login(username,password)
        if user:
            self.login(user)
            self.redirect('/blog')
        else:
            error="Invalid login"
            self.render("login.html",error=error)

class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect("/signup")

class NewPost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by = db.StringProperty()

    #def render(self):
       # self.render_text = self.content.replace('\n','<br>')
        #return render_str("all_post.html",p=self)


class BlogHandler(Handler):
    def get(self, subject="", content="", username="",allUserPosts="",created_by=""):
        allposts = db.GqlQuery("select * from NewPost order by created desc limit 10")
        if self.user:
            allUserPosts = NewPost.all().filter('created_by =', self.user.name).get()

        print self.request.cookies.get(self.user)
        print "In bloghandler......"
        print self.user
        self.render("all_post.html", allposts=allposts , username=self.user, allUserPosts=allUserPosts)


class NewPostHandler(Handler):
    def get(self, error="", subject="", content="", created_by=""):
        # id = new_post.key().id()
        self.render("new_post.html", error=error, subject=subject, content=content,created_by=created_by, username=self.user)

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        created_by = self.user.name
        if subject and content:

            new_post = NewPost(subject=subject, content=content,created_by=created_by)
            new_post.put()
            post_id = str(new_post.key().id())
            self.redirect("/blog/%s" % post_id)
        else:
            error = "Error occured. Both feilds are required."
            self.render("new_post.html", error=error, subject=subject, content=content, username=self.user)


class PermalinkHandler(Handler):
    def get(self, post_id):
        p = NewPost.get_by_id(int(post_id))

        if not p:
            self.error(404)
            return

        self.render("permalink.html", p=p)

class EditPostHandler(Handler):
    print "entered.................."
    def get(self):
        print "entered......get............"
        if self.user:
            print "entered.........user........."
            p = NewPost.all().filter('created_by =', self.user.name).get()


        if not p:
            print "entered........not user.........."
            self.error(404)
            return
        print ".......loading......"
        self.render("edit_post.html" , p=p)

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        created_by = self.user.name
        p = NewPost.all().filter('created_by =', self.user.name).get()
        if subject and content and p:

            #new_post = NewPost(subject=subject, content=content, created_by=created_by)
            p.subject = subject
            p.content = content

            p.put()
            post_id = str(p.key().id())
            self.redirect("/blog/%s" % post_id)
        else:
            error = "Error occured. Both feilds are required."
            self.render("new_post.html", error=error, subject=subject, content=content, username=self.user)

class DeletePostHandler(Handler):
    def get(self):
        print "entered......get............"
        if self.user:
            print "entered.........user........."
            p = NewPost.all().filter('created_by =', self.user.name).get()


        if not p:
            print "entered........not user.........."
            self.error(404)
            return
        print ".......loading......"
        p.delete()
        #driver = webdriver.Firefox()
        #driver.refresh()
        reload(main)
        self.redirect('/blog')

app = webapp2.WSGIApplication([
    ('/welcome', WelcomeHandler),
    ('/signup', RegisterHandler),
    ('/register', RegisterHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/blog/?', BlogHandler),
    ('/blog/newpost',NewPostHandler),
    ("/blog/([0-9]+)",PermalinkHandler),
    ('/postEdit' , EditPostHandler),
    ('/deletePost', DeletePostHandler)
], debug=True)
