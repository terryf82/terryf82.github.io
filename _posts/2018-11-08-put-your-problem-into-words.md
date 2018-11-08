---
layout: post
title: Put your problem into words, and you just might solve it
excerpt_separator: <!--more-->
comments: true
---

While working on a project the other day I had an interesting experience that really made me think about the nature of problem solving. This particular project requires a web interface that allows users to build complex, nested queries to be run against a database, but without them understanding the technical language required to do that. In essence, it's a query-building tool that returns data that allows the next stage of the project to commence, which involves using that data to build relevant text content.

The complexity in translating the user requirements increases quickly with this tool because there are countless ways a user can request the data. A request may begin simple enough (return a destination) but from there be extended to include other entities (the destination needs at least 3 relevant locations, within x kilometres). Those entities may then have their own sub-entity requirements (each location needs to have a certain number of businesses) and those sub-entities may then have their own requirements (each business need to match at least one of a set of categories)... and so on down the rabbit hole.

Finding a solution to managing this complexity eluded me for a long time, and involved a lot of non-reusable, query-specific setup. As I thought about the problem more deeply I started to workshop different ideas in my head. Instead of processing each part of the query separately, could I process it as a whole?. This got me thinking about better ways of representing the data. As it stood, each chunk of the request was simply a row in a table, but I realised this was making full-scope processing virtually impossible. The idea of using JSON seemed plausible, and I set about planning how to implement it. It wasn't until I then opened up Google and typed "strategies for representing SQL as JSON" that I discovered... [GraphQL](https://graphql.org){:target=_blank}

If you haven't come across it before, GraphQL is a query language for API interactions built by Facebook. Using a highly configurable but intuitive syntax, you can allow a client app (or user) the ability to craft API requests that are easy to understand, validate and resolve at the server.

The point of this post isn't to promote GraphQL though, it's to promote the idea of simply *putting your problem into words*. Too often in software engineering we struggle with complex problems that seem difficult to solve, because we're simply not aware that others have experienced the same problem and possibly already solved it. In the case of my project, a massive pain point was eradicated within 2 hours of reading & watching conference videos, and about 4 hours of implementation. I'm sure there will be challenges ahead as the project makes more advanced use of this tool (there are no silver bullets in software) but the simple act of putting the problem into words and then searching for it, rather than just rolling it around in my own head, has paid off significantly. It's not always easy to do (especially if you're under time pressure) but articulating your problem should be one of the first steps any developer takes when faced with a difficult situation.

{% if page.comments %}
<div id="disqus_thread"></div>
<script>

/**
*  RECOMMENDED CONFIGURATION VARIABLES: EDIT AND UNCOMMENT THE SECTION BELOW TO INSERT DYNAMIC VALUES FROM YOUR PLATFORM OR CMS.
*  LEARN WHY DEFINING THESE VARIABLES IS IMPORTANT: https://disqus.com/admin/universalcode/#configuration-variables*/
/*
var disqus_config = function () {
this.page.url = 2018/11/07/put-your-problems-into-words;  // Replace PAGE_URL with your page's canonical URL variable
this.page.identifier = 2018/11/07/put-your-problems-into-words; // Replace PAGE_IDENTIFIER with your page's unique identifier variable
};
*/
(function() { // DON'T EDIT BELOW THIS LINE
var d = document, s = d.createElement('script');
s.src = 'https://thenextscreen.disqus.com/embed.js';
s.setAttribute('data-timestamp', +new Date());
(d.head || d.body).appendChild(s);
})();
</script>
<noscript>Please enable JavaScript to view the <a href="https://disqus.com/?ref_noscript">comments powered by Disqus.</a></noscript>
{% endif %}

