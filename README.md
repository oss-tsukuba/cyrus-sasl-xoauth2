# cyrus-sasl-xoauth2-idp

This is a plugin of [XOAUTH2](https://developers.google.com/gmail/xoauth2_protocol) for Cyrus SASL.  The JWT is verified by the issuer's public key.

## Required packages
* [Cyrus SASL](https://github.com/cyrusimap/cyrus-sasl)
* [SciTokens](https://github.com/scitokens/scitokens-cpp)

### RPM
- cyrus-sasl-devel
- scitokens-cpp-devel

### Debian
- libsasl2-dev, sasl2-bin
- libscitokens-dev

## Build and install

```
./autogen.sh
./configure --libdir=$(pkg-config --variable=libdir libsasl2)
make
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
    xoauth2_issuers: xxxx
    ```

## Client-side configuration

* `${sasl_plugin_dir}/{service_name}.conf`:

    ```
    xoauth2_user_claim: xxxx
    ```
