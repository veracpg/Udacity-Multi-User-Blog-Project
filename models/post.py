
### POST Class Model ###

from google.appengine.ext import db

class Post(db.Model):
    
    content = db.TextProperty(required = True)
    subject = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user = db.ReferenceProperty(User)
    likes = db.IntegerProperty(default=0)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)