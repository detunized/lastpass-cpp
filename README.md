LastPass C++ API
================

[![Build Status](https://travis-ci.org/detunized/lastpass-cpp.png?branch=master)](https://travis-ci.org/detunized/lastpass-cpp)

## No longer supported

This project is no longer supported. There's a fully supported and regularly 
updated C# library that implements access to a veriety of password managers, 
including LastPass. Please check out 
[Password Manager Access](https://github.com/detunized/password-manager-access).

---

**This is unofficial LastPass API.**

There are also [Ruby](https://github.com/detunized/lastpass-ruby) and
[C#/.NET](https://github.com/detunized/lastpass-sharp) ports available.

This library implements fetching and parsing of LastPass data.  The library is
still in the proof of concept stage and doesn't support all LastPass features
yet.  Only account information (logins, passwords, urls, etc.) is available so
far.

There is a low level API which is used to fetch the data from the LastPass
server and parse it. Normally this is not the one you would want to use. What
you want is the `Vault` class which hides all the complexity and exposes all
the accounts already parsed, decrypted and ready to use. See the example
program for detail.

A quick example of accessing your account information:

```cpp
#include <iostream>
#include <lastpass/vault.h>

int main()
{
    auto vault = Vault::create("username", "password");
    for (auto const &i: vault.accounts())
    {
        std::cout << "      id: " << i.id() << '\n'
                  << "    name: " << i.name() << '\n'
                  << "username: " << i.username() << '\n'
                  << "password: " << i.password() << '\n'
                  << "   group: " << i.group() << '\n'
                  << "     url: " << i.url() << '\n'
                  << '\n';
    }

    return 0;
}
```

The blob received from LastPass could be safely stored locally (it's well
encrypted) and reused later on.


LostPass iOS App
----------------

There's an iOS app called [LostPass](http://detunized.net/lostpass/) that is
based on this library (well almost).  If you are a LastPass 
user it would have made your life much easier if I didn't have to take it down
from the App Store. Now it's open source and if you have a developer account
or a jailbroken phone you could build it and install it on the phone. The
source code is [here](https://github.com/detunized/LostPass).


Contributing
------------

Contribution in any form and shape is very welcome.  Have comments,
suggestions, patches, pull requests?  All of the above are welcome.


License
-------

The library is released under [the MIT
license](http://www.opensource.org/licenses/mit-license.php).
