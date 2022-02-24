# cyrus-sasl-xoauth2

This is a plugin implementation of [XOAUTH2](https://developers.google.com/gmail/xoauth2_protocol).

FYI: if you are forced to use XOAUTH2-enabled SMTP / IMAP servers by your employer and want to keep using your favorite \*nix MUA locally, the following detailed document should help a lot: http://mmogilvi.users.sourceforge.net/software/oauthbearer.html (DISCLAIMER: in contrast to the document's author, I'd rather read and write emails on my browser a lot.  I haven't tested it personally)

## Releases

* [v0.2 (Apr 28, 2020)](https://github.com/moriyoshi/cyrus-sasl-xoauth2/releases/tag/v0.2)
* [Development (Apr 28, 2020)](https://github.com/moriyoshi/cyrus-sasl-xoauth2/releases/tag/edge)

## Building and installation

```
./autogen.sh
./configure
sudo make install
```

## Server-side configuration

* `${sasl_plugin_dir}/{service_name}.conf`:

    ```
    log_level: DEBUG
    mech_list: xoauth2
    client_id: xxxxx
    client_secret: xxxxx
    introspection_url: https://xxxxx/auth/realms/yyyy/protocol/openid-connect/token/introspect
    ```

