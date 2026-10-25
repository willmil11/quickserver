# Quickserver v1.1.8
## What is this?
This is a webserver that I made in C, it supports ipv6, ipv4, https, and http.

## How do I use this?
You'll need to compile the file, which is easy as there are no dependencies to pull or whatever just one script which is basically one command, so open your shell (and make sure you have gcc installed) then run:
```bash
fish compile.fish
```
And if you don't have the fish shell, I think you can basically use whatever shell you want as the script only uses basic things like echo and the gcc command. So if you want to use bash instead:
```bash
bash compile.fish
```
And it'll work :)
<br>
**Edit**: Not only does it work, but you don't have to worry about clang masquarading as gcc on macos or termux because this now also compiles with clang.

Then just move it into your path so you can easily call it with 'quickserver' or you can just use it like './quickserver' then just do 'quickserver help' or './quickserver help' depending if it's in your path or not to have a little guide.

## Future updates:
- [ ] Add file caching.
- [x] Fix an https bug that makes it so it doesn't work with stupid software like curl and only with smart software like browsers.
- [ ] I know there must be memory leaks hiding, I'll find them and fix them.

## Version history:
- v1.1.8 - Fixed small security vunerability caused by previous patch, basically when you tried accessing something outside the serve dir, if it existed the `realpath()` check triggered and it would respond with 403, if it didn't exist the check would'nt trigger and you got a normal 404 instead. Point being that anyone could check whether a file/directory existed or not outside the serve dir by checking the http code this way. Now it's 404 for both cases so it's fixed. Also the code now compiles on clang. - yours truly at 3:57am through termux, good night.
- v1.1.7 - Fixed security vunerability (path backtracing attack).
- v1.1.6 - Fixed HTTPS certificate chain bug that caused SSL errors with curl and other clients.
- v1.1.5 - Added query string to log.
- v1.1.4 - Fixed another bug in the default 404.html page.
- v1.1.3 - Fixed a bug in the default 404.html page.
- v1.1.2 - Fixed memory leaks, and a double free.
- v1.1.1 - Added correct query string handling.
- v1.0.1 - Fixed bugs.
- v1.0.0 - Initial release.

## How to contact me?
- Email: willmil111012@gmail.com
- Discord: willmil11

## License
Link to license (<a href="./LICENSE.md">click here</a>)
