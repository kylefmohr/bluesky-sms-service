# bluesky-sms-service
This program utilizes [Bluesky's atproto API](https://atproto.com/docs) to host a simple Python application in Google Cloud, utilizing a number of Google Cloud services.

## To use!
Simply text `register <your bsky.social handle> <your bsky.social app password>` to `+1-414-432-4321`, and you'll be automatically registered. For example, you might send `register dril.bsky.social asdf-jklq-wert-yuio` to `414-432-4321`, and then any subsequent messages sent to this number will be posted to your Bluesky account. To register an app password, you can do so [here](https://bsky.app/settings/app-passwords). Login passwords are *not* supported. Also, please note that you will *not* receive any messages back from this number, due to increasingly strict anti-spam laws. 

After you've registered, you can text that number any time you want to post to Bluesky! Photos are supported as well! Messages longer than 300 characters will be automatically threaded, but just a heads up that due to the way longer text messages are handled, it may not appear on your feed for 2-3 minutes. Normal length posts are posted almost instantly. 

Let me know if you run into issues, you can raise an issue here or contact me via [Bluesky here](https://bsky.app/profile/assf.art)
