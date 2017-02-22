### COMMENTS Class Model ###

from google.appengine.ext import db

class Comment(db.Model):
    comment = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user = db.ReferenceProperty(User)
    post = db.ReferenceProperty(Post)

    @classmethod
    def count_by_pid(cls, post_id):
        c = Comment.all().filter('post=', post_id)
        return c.count()

    @classmethod
    def all_by_pid(cls, post_id):
        c = Comment.all().filter('post=', post_id).order('created')
        return c