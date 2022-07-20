# cyrus-sasl-xoauth2

This is a plugin implementation of [XOAUTH2](https://developers.google.com/gmail/xoauth2_protocol).

## Preparing

* install [SciTokens](https://github.com/scitokens/scitokens-cpp)

## Building and installation

```
./autogen.sh
./configure
sudo make install
```

## Server-side configuration

* `${sasl_plugin_dir}/{service_name}.conf`:

    ```
    log_level: 7
    mech_list: xoauth2
    xoauth2_scope: xxxx
    xoauth2_aud: xxxx
    xoauth2_user_claim: xxxx

    ```

