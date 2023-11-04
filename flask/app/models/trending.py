from app.extensions import db

# table database user
class Trending(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    count_tweet = db.Column(db.Integer, default=0)
    # fungsi serialize untuk mengembalikan data dictionary
    def serialize(self): 
        return {
            "id": self.id,
            "username": self.username,
            "count_tweet":self.count_tweet,
        }