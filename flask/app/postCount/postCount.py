from app.extensions  import db
from app.models.count_tweet import CountTweets
from app.models.user import Users
from app.models.tweet import Tweets



def count_tweet():
    # Query new data
    users = Users.query.all()
    user_posts = {}
    for user in users:
        count_tweet = Tweets.query.filter_by(user_id=user.user_id).count()
        user_posts[user.username] = count_tweet

    sorted_users = sorted(user_posts.items(), key=lambda x: x[1], reverse=True)

    # Update the Trending table with new data
    existing_trending_users = CountTweets.query.all()
    existing_users = {trending_user.username: trending_user for trending_user in existing_trending_users}

    for username, count_tweet in sorted_users:
        if username in existing_users:
            # Update existing Trending entry
            trending_user = existing_users[username]
            trending_user.count_tweet = count_tweet
        else:
            # Create a new Trending entry
            trending_user = CountTweets(username=username, count_tweet=count_tweet)
            db.session.add(trending_user)

    db.session.commit()
