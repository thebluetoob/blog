---
title: Building This Blog
published: true
date: 2019-09-12 12:00
---

# [](#header-1)TL;DR
Check Jekyll markdown files in to Git --> TLS connection from Github to VPS running [webhook](https://github.com/adnanh/webhook) proxied using Nginx + Lets Encrypt; MiTM'd by Cloudflare --> Jekyll rebuilds blog, dumps fresh HTML to directory --> Nginx serves static HTML.

# [](#header-1)But Why?
I've been meaning to start blogging again for quite a while now but really wanted to figure out this newfangled static site generator thing that all of the cool kids were talking about.

Hosting it using Github pages didn't really seem like it'd be the best way to learn so I decided to set up my blog using Github as a code base and a VPS I am already using for hosting my CTFd instance for web hosting.

When I eventually get sick of having to manage the lets encrypt certs + VPS + Webhook config + Nginx config hopefully it won't be too hard to switch this over to Github pages.

Having static HTML served behind cloudflare will also hopefully make things pretty snappy.

I'm also kind of using this post as a way to document how I built this for myself because I'm sure not going to write any other form of documentation locally.

# [](#Header-1)Technology Stack
# [](#Header-2)Operating System
Pretty simple. Minimal installation of CentOS 7 x64 with a vanilla VPS provider. Already had this VPS hosting [CTFd](https://github.com/CTFd/CTFd) proxied behind nginx with a Lets Encrypt certificate for one of my subdomains so it seemed like a natural fit to put my blog on here too.

I created additional limited permission users (and changed the appropriate [permissions](https://askubuntu.com/questions/767504/permissions-problems-with-var-www-html-and-my-own-home-directory-for-a-website/767534#767534)) to run the shit tonne of ruby that needed to be brought to the party to build this blog but otherwise it's a bog standard CentOS 7 image.

# [](#Header-2)Applications
# [](#Header-3)Jekyll
So Jekyll of course requires ruby which was a bit awkward to get installed on CentOS 7 so I ended up using [rbenv](https://www.digitalocean.com/community/tutorials/how-to-install-ruby-on-rails-with-rbenv-on-centos-7) - this required a $PATH update on CentOS 7.

Once Ruby was installed I grabbed a copy of a [Jekyll theme](https://github.com/tocttou/hacker-blog) I liked (I also learnt you can't fork a public repo in to a private one) and used bundler to install _even more_ ruby things which I promptly added to the .gitignore file.

Then I used bundler to install Jekyll itself mostly using the [official documentation](https://jekyllrb.com/docs/) as a guide.

I had to make [a](https://github.com/jekyll/jekyll/issues/156) [few](https://github.com/jekyll/jekyll/issues/5267#issuecomment-241379902) changes to make things render nicely and generate HTML respectively but then I was off to the races as far as Jekyll goes.

# [](#Header-3)Nginx
As mentioned previously, I already had Nginx installed and running as a reverse proxy for CTFd to provide authentication so it was a natural choice to have nginx serve the static HTML, although authentication was of course not necessary.

I ended up with the following configuration files defined in my /etc/nginx/sites-enabled directory:
*   _ctfd.thebluetoob.com_ presenting the user with an authentication challenge and upon passing it, proxying their requests through to CTFd being served by [gunicorn](https://github.com/CTFd/CTFd/wiki/Advanced-Deployment#gunicorn).
*   _webhook.thebluetoob.com_ being a (you guessed it) endpoint for my Github webhooks to go through, similar to the above it proxies the requests coming in to a service listening on localhost. Will get to the webhook configuration a bit later.
*   _blog.thebluetoob.com_ being served as static HTML files from a directory on the server by nginx.

All three of the above subdomains have lets encrypt certificates being autorenewed by certbot and are all proxied behind Cloudflare for caching and whatever level of DDoS protection you get on the free plan. 

I've also got a cron job that uses IP tables to limit incoming connections only to Cloudflare exit IPs, mostly to reduce noise in my logs - I'm not too concerned of someone decloaking the IP to this VPS.

# [](#Header-3)Webhook
As mentioned above I use [webhook](https://github.com/adnanh/webhook) as a webhook daemon listening on localhost with the TLS connection managed by certbot/lets encrypt/nginx and proxied as per the above notes.

I configured the webhook within Git to use JSON for the content type with SSL/a randomly generated secret and then used this hooks.json file for _webhook_.

```js
[
  {
    "id": "regenerate-website",
    "execute-command": "/path/to/script.sh",
    "command-working-directory": "/path/to/git/repository/",
    "trigger-rule": {
      "match": {
        "type": "payload-hash-sha1",
        "secret": "itsasecret",
        "parameter": {
          "source": "header",
          "name": "X-Hub-Signature"
        }
      }
    }
  }
]

```

Future Ben when you're reading this, don't hardcode the secret in the JSON file. This JSON file isn't checked in anywhere so it's not _that_ big a deal but it's still better practice to use an envar instead. Also goes for anyone reading this who is _not_ future Ben.

The above JSON file as well as the shell script I wrote to perform the update were taken from [this](https://dev.to/severo/using-webhooks-to-update-a-self-hosted-jekyll-blog-59al) extremely useful blog post by Sylvain Lesage (thank you!).

All my shell script does is clone a copy of the repository using read-only deploy keys over SSH; purge the nginx HTML folder; call Jekyll to rebuild the website and dump the HTML in to the aforementioned nginx HTML directory.

# [](#header-1)Lessons Learnt
I learnt a bunch of new things building this blog to be honest. I set out to learn more about how static site generators and Git works and succeeded! So I'm happy.

I think part of why I've held off on blogging for so long is the fear of not having anything all that interesting or noteworthy to say and who really cares? I still feel that way but have decided that I'll just be writing this blog for myself. Not to get a job or to look like a super cool hacker man, just to have another avenue where I can learn new things.

The other thing that setting this blog up taught me is _holy crap I totally get why everyone shifted to medium_. If I wasn't so hellbent on making this a learning exercise I would've thrown in the towel super early on and just posted my VulnHub writeups to medium or wix or squarespace or wordpress or blogspot or whatever. I do wonder if I'm out of touch or if it's the children who are wrong but it seemed a lot easier to carve out a little corner of the internet for your thoughts when I was younger than it is today.

I'm pretty sure it's just that what I'm with isn't it, and what's _it_ seems weird and scary to me. But at least now that _it_ doesn't include Git/webhooks/Jekyll/Ruby as much.

I'll hopefully be publishing some VulnHub writeups and other content soon. I've also got a SQL backup of my five year old blog with password cracking notes but I'm not sure when I'll get around to loading, converting, munging, and posting that to here.