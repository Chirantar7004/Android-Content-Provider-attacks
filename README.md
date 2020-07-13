# Content-Providers
Content Providers are methods of sharing data. Content providers are primarily used for searching the data within application and using widgets on top of application data. Both structured data such as SQLlite db and unstructured data such as image files can be be saved using content provider. In addition, they offer a granular control over accessing their data. More on it [here](https://developer.android.com/guide/topics/providers/content-providers).

# Content-Provider-attacks
However, a wrong permission model could lead to to hijack the leaking content providers so that external apps could read their data. It is quite important to understand this secure coding practice and proactively follow it with best android security practices.

Solution directory contains the exploit methodology as well as the commands and Apk directory contains the apps that got broke due to this vulnerability.
