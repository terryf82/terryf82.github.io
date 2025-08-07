---
hide:
  - toc
---

# pitfallen.net

### (`pit·fawl·en`) *`[adj]`* *Educated in the ways of getting things to work, through full enumeration of all routes leading to failure.*

---

## New Posts
{% for post in get_blog_posts() %}
### [{{ post.title }}](/{{ post.url }})
{{ post.date_obj }}

*{{ post.summary }}*

---
{% endfor %}