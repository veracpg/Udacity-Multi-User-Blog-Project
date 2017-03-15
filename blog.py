import os
import re
import random
import hashlib
import hmac 
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.api import users

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'chave'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
  def get(self):
     self.render('front_page.html')

### USER ###

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

def users_key(group='default'):
    return db.Key.from_path('users', group)

 ### USER ID object Class Model ###

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

### POST Class Model ###
         
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    
    content = db.TextProperty(required = True)
    subject = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user = db.ReferenceProperty(User, required = True, collection_name="blogs")

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)


### COMMENTS Class Model ###

class Comment(db.Model):
    comment_text = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user = db.ReferenceProperty(User, required = True)
    post = db.ReferenceProperty(Post, required = True)

    @classmethod
    def count_by_pid(cls, post_id):
        c = Comment.all().filter('post=', post_id)
        return c.count()

    @classmethod
    def all_by_pid(cls, post_id):
        c = Comment.all().filter('post=', post_id).order('created')
        return c

### LIKES Class Model ###
class Like(db.Model):
    user = db.ReferenceProperty(User, required = True)
    post = db.ReferenceProperty(Post, required = True)

    @classmethod
    def count_by_pid(cls, post_id):
        l = Like.all().filter('post=', post_id)
        return l.count()
    
    @classmethod
    def check_like(cls, post_id, user_id):
        cl = Like.all().filter('post=', post_id).filter('user=', user_id)
        return cl.count()      

### UNLIKES Class Model ###
class Unlike(db.Model):
    user = db.ReferenceProperty(User, required = True)
    post = db.ReferenceProperty(Post, required = True)

    @classmethod
    def count_by_pid(cls, post_id):
        ul = Unlike.all().filter('post=', post_id)
        return ul.count()
    
    @classmethod
    def check_unlike(cls, post_id, user_id):
        cul = Unlike.all().filter('post=', post_id).filter('user=', user_id)
        return cul.count()      


### BLOG FRONT ###

class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('blog.html', posts = posts)

### POST PAGE ###

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        
        # error 404 if criteria does not match
        if not post:
            self.error(404)
            return
        # Get likes, unlikes & comments

        likes = Like.count_by_pid(post_id)
        unlikes = Unlike.count_by_pid(post_id)
        post_comments = Comment.all().filter('post=', post_id).order('created')
        comments_count = Comment.count_by_pid(post_id)

        self.render('link.html', post = post,
                    likes = likes,
                    unlikes = unlikes,
                    comment = post_comments,
                    comments_count = comments_count)
        
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        user_id = User.by_name(self.user.name)
        comments_count = Comment.count_by_pid(post)
        post_comments = Comment.all().filter('post=', post_id).order('created')
        likes = Like.count_by_pid(post)
        unlikes = Unlike.count_by_pid(post)
        previously_liked = Like.check_like(post, user_id)
        previously_unliked = Unlike.check_unlike(post, user_id)
        
        if self.user:
            if self.request.get('like'):
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    if previously_liked == 0:
                        l = Like(post = post,
                                user = User.by_name(self.user.name))
                        l.put()
                        self.redirect('/%s' % str(post.key().id()))
                    else:
                        error = "Dude you already like this post!"
                        self.render('link.html', post = post,
                                    likes = likes,
                                    unlikes = unlikes,
                                    comment = post_comments,
                                    comments_count=comments_count,
                                    error = error)
                else:
                    error = "Dude people that like their own posts are just sad!"
                    self.render('link.html', post = post,
                                likes = likes,
                                unlikes = unlikes,
                                comment =post_comments,
                                comments_count=comments_count, 
                                error = error)

            if self.request.get("unlike"):
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    if previously_unliked == 0:
                        ul = Unlike( post = post, user = User.by_name(self.user.name))
                        ul.put()
                        self.redirect('/%s' % str(post.key().id()))
                    else:
                        error = "Dude you already unlike this post!"
                        self.render('link.html', post = post,
                                    likes = likes,
                                    unlikes = unlikes,
                                    comment = post_comments,
                                    comments_count = comments_count,
                                    error = error)
                else:
                    error = "Dude don't be hard on yourself!"
                    self.render('link.html', post = post,
                                likes = likes,
                                unlikes = unlikes,
                                comment = post_comments,
                                comments_count=comments_count,
                                error = error)

            if self.request.get("add_comment"):
                comment_text = self.request.get("comment_text")

                if comment_text:
                    c = Comment(post=post, user=User.by_name(self.user.name), comment_text=comment_text)
                    c.put()
                    self.redirect('/%s' % str(post.key().id()))
                else:
                    error = "Please write your comment"
                    self.render('link.html', post = post,
                                likes = likes,
                                unlikes = unlikes,
                                comment=post_comments,
                                comments_count=comments_count,
                                error = error)

            if self.request.get("edit"):
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    self.render ("editpost.html")
                else:
                    error = "Not cool to edit other user post"
                    self.render('link.html', post = post,
                                likes = likes,
                                unlikes = unlikes,
                                post_comments=post_comments,
                                comments_count=comments_count,
                                error = error)
            if self.request.get("delete"):
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    db.delete(key)
                    self.redirect ('/blog')
                else:
                    error = "Not cool to delete other user post"
                    self.render('link.html', post = post,
                                likes = likes,
                                unlikes = unlikes,
                                post_comments=post_comments,
                                comments_count=comments_count,
                                error = error)
        else:
            self.redirect("/signup")

### EDIT POST ###

class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
       
        if self.user:
            if post.user.key().id() == User.by_name(self.user.name).key().id():
                self.render('editpost.html', post = post)
            else:
                self.response.out.write ("Not cool to edit other user post")
        else:
            self.redirect("/signup")

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        subject = self.request.get('subject')
        content = self.request.get('content')
        user_id = User.by_name(self.user.name)

        if self.request.get("update"):
            if post.user.key().id() == User.by_name(self.user.name).key().id():
                if subject and content:
                    subject = subject
                    content = content
                    p = Post(parent = blog_key(), subject = subject, content = content, user = user_id)
                    p.put()
                    self.redirect('/%s' % str(p.key().id()))
                else:
                    error = "I think you forgot something..."
                    self.render('editpost.html', subject = subject,
                                content = content,
                                error = error)
            else:
                self.response.out.write("Not cool to edit other user post")

        elif self.request.get("cancel"):
            self.redirect('/%s' % str(p.key().id()))

### EDIT COMMENT ###

class EditComment(BlogHandler):
    def get(self, post_is, comment_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Commment.get_by_id(int(comment_id))

        if comment:
            if comment.user.name == self.user.name:
                self.render("editcomment.html", comment_text = comment_text)
            else:
                error = "Not cool to edit other user comment"
                self.render("editcomment.html",comment_text = comment_text, error = error)
        else:
            self.write("Heads up this comment no longer exists")
    
    def post(self, post_id, comment_id):
        if self.request.get("update_comment"):
            comment = Commment.get_by_id(int(comment_id))

            if comment.user.name == self.user.name:
                comment.text = self.request.get("comment_text")
                comment.put()
                self.redirect('/%s' % str(p.key().id()))
            else:
                error = "Not cool to edit other user comment"
                self.render("editcomment.html",comment_text = comment_text, error = error)
        elif self.request.get("cancel"):
            self.redirect('/%s' % str(p.key().id()))
       
### DELETE COMMENT ###

class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Commment.get_by_id(int(comment_id))

        if comment:
            if comment.user.name == self.user.name:
                db.delete(comment)
                self.redirect('/%s' % str(p.key().id()))
            else:
                self.write("Not cool delete other user comment")
        else:
            self.write("Heads up this comment no longer exists")
    

### NEW POST ###

class NewPost(BlogHandler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        user_id = User.by_name(self.user.name)

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, user = user_id)
            p.put()
            self.redirect('/%s' % str(p.key().id()))
        else:
            error = "Subject and Content not valid"
            self.render('newpost.html', subject = subject, content = content, error = error )



### Parameters sign up validation

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

### Sign Up ###

class Signup(BlogHandler):
    def get(self):
        self.render('signup-form.html')
    
    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
    
        params = dict(username = self.username, email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "Username not valid"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Password not valid"
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Password don't match"
            have_error = True
        
        if not valid_email(self.email):
            params['error_email'] = "Email not valid"
            have_error = True
        
        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Valid_Signup(Signup):
    def done(self):
        self.redirect('/welcome' + self.username)

class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            error_msg = 'That user already exists.'
            self.render('signup-form.html', error_username = error_msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')


### Welcome ###

class Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')
        
### Login ###

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

### Logout ###

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                                ('/signup', Register),
                                ('/welcome', Welcome),
                                ('/login', Login),
                                ('/blog', BlogFront),
                                ('/newpost', NewPost),
                                ('/([0-9]+)', PostPage),
                                ('/logout', Logout),
                                ('/edit/([0-9]+)', EditPost),
                                ],
                                debug=True)

