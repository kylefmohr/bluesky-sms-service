# bluesky-sms-service
This program utilizes [Bluesky's atproto API](https://atproto.com/docs) to host a simple Python application in Google Cloud, utilizing a number of Google Cloud services.

## tl;dr:
Send an SMS to `+1 414-432-4321` with the message: `register <your bsky.social handle> <your bsky.social app password>`. Then, you can send an SMS to that same number at any time in order to post on Bluesky! 


## More details: 
For example, you might send `register dril.bsky.social asdf-jklq-wert-yuio` to `414-432-4321`, and then any subsequent messages sent to this number will be posted to your Bluesky account. To register an app password, you can do so [here](https://bsky.app/settings/app-passwords). Login passwords are *not* supported. Also, please note that you will *not* receive any messages back from this number, due to increasingly strict anti-spam laws. 

After you've registered, you can text that number any time you want to post to Bluesky! Photos are supported as well! Messages longer than 300 characters will be automatically threaded, but just a heads up that due to the way longer text messages are handled, it may not appear on your feed for 2-3 minutes. Normal length posts are posted almost instantly. 

Let me know if you run into issues, you can raise an issue here or contact me via [Bluesky here](https://bsky.app/profile/assf.art)

## To unregister!
Simply text `!unregister <your bsky.social handle>` to `+1-414-432-4321`, and your account will be unregistered. For example, you might send `!unregister dril.bsky.social` to `414-432-4321`, and your account information will be removed from this service.


TODO:

 ~- Move off of BigQuery, as it wasn't the right choice, especially due to the inability to delete entries for the first 90 minutes after they were created.~
   ~- Possibly Cloud Firestore~
   
 - Only add a sender (i.e. a bsky username and the associated phone number) iff the secret was successfully registered as well
 - More robust protection preventing people from accidentially posting their app password
 - Fix handles not linking properly when you post via this platform ([see this example](https://bsky.app/profile/assf.art/post/3lc4v7dajqs2k))
   - Also, does this apply to normal URLs? If so, fix that too
