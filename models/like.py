### LIKES Class Model ###

from google.appengine.ext import db

class Like(db.Model):
    user = db.ReferenceProperty(User)
    post = db.ReferenceProperty(Post)

    @classmethod
    def count_by_pid(cls, post_id):
        l = Like.all().filter('post=', post_id)
        return l.count()
    
    @classmethod
    def check_like(cls, post_id, user_id):
        cl = Like.all().filter('post=', post_id).filter('user=', user_id)
        return cl.count()      