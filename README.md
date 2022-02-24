# cyrus-sasl-xoauth2

This is a plugin implementation of [XOAUTH2](https://developers.google.com/gmail/xoauth2_protocol).

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

