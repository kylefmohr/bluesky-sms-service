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


### TODO:

 - ~Move off of BigQuery, as it wasn't the right choice, especially due to the inability to delete entries for the first 90 minutes after they were created.~
   - ~Possibly Cloud Firestore~ Done
 - Use something better than Secret Manager as I don't think this is the right use-case for that service. Maybe OAuth?
   - I am actually able to send outbound messages from this number now. It could be feasible to have people send this script their username only, and then it responds with a sign-in link (if I am understanding OAuth correctly). I've never implemented OAuth before, so this may take time
   - Also if I do that, I'd like there to be no breaking changes for current users. Either by supporting both passwords *and* OAuth, or by transitioning these people to OAuth behind the scenes. 
   
 ~- More robust protection preventing people from accidentially posting their app password~
 - ^ Right now we have good protection against this at the cost of not currently supporting multiple accounts per phone number. This may come in a later update, but for now, playing it safe.
 - ~Fix handles not linking properly when you post via this platform ([see this example](https://bsky.app/profile/assf.art/post/3lc4v7dajqs2k))~
   - ~Also, does this apply to normal URLs? If so, fix that too~
 - Support for video attachments
   - Maybe. This is a very low priority: videos sent using MMS are extremely compressed, take a long time to send, and are more pricey to receive. 
 
