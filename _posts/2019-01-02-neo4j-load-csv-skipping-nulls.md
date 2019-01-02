---
layout: post
title: Neo4J - Skipping null values when using LOAD CSV
excerpt_separator: <!--more-->
comments: true
---

A recent project at work required transforming a CSV of destination IDs into parent-child relationships in a graph database - a simple enough task, until I realised that there were a variable number of relations to be created for each destination (row). Most had 1 - 4, but some had zero, and were in effect useless rows that needed to be skipped:

	+------------------------------------------------+
	| Parent | Child 1 | Child 2 | Child 3 | Child 4 |
	+------------------------------------------------+
	|    101 |    102 |      103 |     104 |     105 |
	|    110 |    112 |      113 |         |         |
	|    120 |        |          |         |         |
	|    130 |    132 |      133 |     134 |         |
	+------------------------------------------------+

Each child ID also needed to be checked to confirm it matched an existing node, otherwise it was irrelevant and should be ignored (the functional equivalent of null).

There were over ten files to process in this way, some containing up to 20 possible relations per destination, so executing a separate cypher query for each column manually seemed inefficient and prone to error. Thankfully, the cypher syntax is flexible enough to allow easy processing of variable length data in this format (that is, a single statement can correctly handle rows that have all 4 relations as well as those that have less than 4, even zero):

```
using periodic commit
load csv from ".../parent-child-relationships.csv" as row
unwind range(1,4) as i
match (parent:Destination {id: row[0]})
match (child:Destination {id: row[i]})
merge (parent)-[r:IS_PARENT_OF]->(child)
return parent
```

Essentially the *unwind range(1, 4)* allows us to iterate through the columns of a single row, and take any necessary action on each value. True null handling would require only adding a case statement to conditionally continue if *row[i] <> ""*.

The ability of Cypher & Neo4J to speed up ingestion of inconsistent CSV data continues to impress me and I'm looking forward to learning more of the advanced features as the project progresses.

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

