### UNLIKES Class Model ###

from google.appengine.ext import db

class Unlike(db.Model):
    user = db.ReferenceProperty(User)
    post = db.ReferenceProperty(Post)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def count_by_pid(cls, post_id):
        ul = Unlike.all().filter('post=', post_id)
        return ul.count()
    
    @classmethod
    def check_unlike(cls, post_id, user_id):
        cul = Unlike.all().filter('post=', post_id).filter('user=', user_id)
        return cul.count()      
